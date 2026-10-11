
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function auth(req,res,next){
  const token = req.headers.authorization?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'No token'});
  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  }catch(e){ return res.status(401).json({error:'Invalid token'})}
}

// ADMIN LOGIN
app.post('/api/auth/admin-login', async (req,res)=>{
  const { email, password } = req.body;
  const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email, password });
  if(error) return res.status(400).json({error: error.message});
  if(email !== process.env.ADMIN_EMAIL) return res.status(403).json({error:'Not admin'});
  const token = jwt.sign({ id: data.user.id, email, role:'admin', adm_number:null }, process.env.JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: data.user });
});

// ADMIN admits student - ONLY adm_number, name, level + fees
app.post('/api/admin/admit', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { adm_number, full_name, level, total_fees } = req.body;
  if(!adm_number || !full_name || !level) return res.status(400).json({error:'adm_number, full_name, level required'});

  const { data, error } = await supabaseAdmin.from('students').insert({
    adm_number: adm_number.trim().toUpperCase(),
    full_name: full_name.trim(),
    level: level.trim(),
    course: level.trim(),
    total_fees: parseInt(total_fees)||0,
    paid_amount: 0,
    is_registered: false
  }).select().single();

  if(error) return res.status(400).json({error: error.message + ' (maybe adm number exists)'});
  res.json(data);
});

// STUDENT SIGNUP - only if admitted, details must match
app.post('/api/auth/student-signup', async (req,res)=>{
  const { adm_number, full_name, level, password } = req.body;
  if(!adm_number || !full_name || !level || !password) return res.status(400).json({error:'All fields required'});

  const adm = adm_number.trim().toUpperCase();
  const name = full_name.trim();
  const lvl = level.trim();

  // Check if admitted
  const { data: admitted, error: findErr } = await supabaseAdmin.from('students').select('*').eq('adm_number', adm).single();
  if(findErr || !admitted) return res.status(404).json({error:'Admission not found. Contact admin.'});
  if(admitted.is_registered) return res.status(400).json({error:'Already registered. Please login.'});

  // Must match name and level (case-insensitive for name, exact for level)
  if(admitted.full_name.toLowerCase() !== name.toLowerCase()){
    return res.status(400).json({error:`Name does not match admin record. Expected: ${admitted.full_name}`});
  }
  if(admitted.level.toLowerCase() !== lvl.toLowerCase()){
    return res.status(400).json({error:`Level does not match. Expected: ${admitted.level}`});
  }

  // Create auth user - email is synthetic: adm_number@rakti.local
  const email = `${adm.toLowerCase()}@rakti.local`;
  const { data: authUser, error: authErr } = await supabaseAdmin.auth.admin.createUser({
    email, password, email_confirm: true,
    user_metadata: { adm_number: adm, full_name: admitted.full_name, level: admitted.level }
  });
  if(authErr) return res.status(400).json({error: authErr.message});

  // Link student record to auth user
  const { data: updated, error: updErr } = await supabaseAdmin.from('students').update({
    id: authUser.user.id,
    email,
    is_registered: true
  }).eq('adm_number', adm).select().single();

  if(updErr) return res.status(400).json({error: updErr.message});

  await supabaseAdmin.from('notifications').insert({
    for_adm_number: adm,
    for_user_id: authUser.user.id,
    title: 'Registration Successful',
    message: `Welcome ${admitted.full_name}! Your account linked to ${adm}. Balance is KES ${admitted.balance || admitted.total_fees}.`
  });

  const token = jwt.sign({ id: authUser.user.id, adm_number: adm, role:'student' }, process.env.JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: authUser.user, student: updated });
});

// STUDENT LOGIN - with adm_number + password (or email)
app.post('/api/auth/student-login', async (req,res)=>{
  const { adm_number, password } = req.body;
  if(!adm_number || !password) return res.status(400).json({error:'adm_number and password required'});
  const adm = adm_number.trim().toUpperCase();
  const email = `${adm.toLowerCase()}@rakti.local`;
  const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email, password });
  if(error) return res.status(400).json({error:'Invalid adm number or password'});

  const { data: student } = await supabaseAdmin.from('students').select('*').eq('adm_number', adm).single();
  const token = jwt.sign({ id: data.user.id, adm_number: adm, role:'student' }, process.env.JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: data.user, student });
});

// ADMIN: get all students
app.get('/api/admin/students', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { data } = await supabaseAdmin.from('students').select('*').order('created_at',{ascending:false});
  res.json(data);
});

// ADMIN: add fees directly
app.post('/api/admin/add-payment', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { adm_number, amount, type } = req.body;
  const adm = adm_number.trim().toUpperCase();
  const { data: student } = await supabaseAdmin.from('students').select('*').eq('adm_number', adm).single();
  if(!student) return res.status(404).json({error:'Student not found'});
  const newPaid = student.paid_amount + parseInt(amount);
  await supabaseAdmin.from('students').update({ paid_amount: newPaid }).eq('adm_number', adm);
  await supabaseAdmin.from('payments').insert({
    adm_number: adm, student_id: student.id, amount: parseInt(amount), type: type||'fees', status:'confirmed', method:'admin_direct'
  });
  const balance = student.total_fees - newPaid;
  await supabaseAdmin.from('notifications').insert({
    for_adm_number: adm, for_user_id: student.id,
    title: 'Fees Payment Added',
    message: `Your fees payment of KES ${amount} was added and balance is KES ${balance}.`
  });
  res.json({ success:true, balance });
});

// STUDENT: submit payment for confirmation
app.post('/api/student/submit-payment', auth, async (req,res)=>{
  if(req.user.role !== 'student') return res.status(403).json({error:'Student only'});
  const { amount, type, method } = req.body;
  const { data, error } = await supabaseAdmin.from('payments').insert({
    adm_number: req.user.adm_number,
    student_id: req.user.id,
    amount: parseInt(amount),
    type, method,
    status:'pending'
  }).select().single();
  if(error) return res.status(400).json({error:error.message});
  res.json(data);
});

// STUDENT: get own data (read only)
app.get('/api/student/me', auth, async (req,res)=>{
  if(req.user.role !== 'student') return res.status(403).json({error:'Student only'});
  const { data: student } = await supabaseAdmin.from('students').select('*').eq('adm_number', req.user.adm_number).single();
  const { data: payments } = await supabaseAdmin.from('payments').select('*').eq('adm_number', req.user.adm_number).order('submitted_at',{ascending:false});
  const { data: notifs } = await supabaseAdmin.from('notifications').select('*').eq('for_adm_number', req.user.adm_number).order('created_at',{ascending:false}).limit(20);
  res.json({ student, payments, notifications: notifs });
});

// ADMIN: pending payments
app.get('/api/admin/pending-payments', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { data } = await supabaseAdmin.from('payments').select('*, students(full_name,adm_number,level)').eq('status','pending').order('submitted_at',{ascending:false});
  res.json(data);
});

// ADMIN: confirm/reject
app.post('/api/admin/confirm-payment', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { payment_id, action } = req.body;
  const { data: payment } = await supabaseAdmin.from('payments').select('*').eq('id', payment_id).single();
  if(!payment || payment.status !== 'pending') return res.status(400).json({error:'Invalid payment'});
  if(action === 'confirmed'){
    await supabaseAdmin.from('payments').update({ status:'confirmed', confirmed_at: new Date().toISOString() }).eq('id', payment_id);
    const { data: student } = await supabaseAdmin.from('students').select('*').eq('adm_number', payment.adm_number).single();
    const newPaid = student.paid_amount + payment.amount;
    await supabaseAdmin.from('students').update({ paid_amount: newPaid }).eq('adm_number', payment.adm_number);
    const balance = student.total_fees - newPaid;
    await supabaseAdmin.from('notifications').insert({
      for_adm_number: payment.adm_number, for_user_id: payment.student_id,
      title: 'Payment Confirmed',
      message: `Your ${payment.type} payment of KES ${payment.amount} confirmed. Balance is KES ${balance}.`
    });
    return res.json({ success:true, balance });
  } else {
    await supabaseAdmin.from('payments').update({ status:'rejected' }).eq('id', payment_id);
    await supabaseAdmin.from('notifications').insert({
      for_adm_number: payment.adm_number, for_user_id: payment.student_id,
      title: 'Payment Not Received',
      message: `Your ${payment.type} payment of KES ${payment.amount} marked as not received.`
    });
    return res.json({ success:true });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=> console.log(`Rakti backend running on http://localhost:${PORT}`));
