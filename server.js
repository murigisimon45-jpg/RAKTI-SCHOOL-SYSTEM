import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
dotenv.config();
const __filename=fileURLToPath(import.meta.url);
const __dirname=path.dirname(__filename);
const app=express();
app.use(cors({origin:'*',methods:['GET','POST','PUT','DELETE','OPTIONS'],allowedHeaders:['Content-Type','Authorization']}));
app.use(express.json());
app.use(express.static(__dirname));
const supabaseAdmin=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_KEY);

function auth(req,res,next){const t=req.headers.authorization?.replace('Bearer ','');if(!t)return res.status(401).json({error:'No token'});try{req.user=jwt.verify(t,process.env.JWT_SECRET);next();}catch(e){return res.status(401).json({error:'Invalid token'})}}
async function isAdmin(id){const {data}=await supabaseAdmin.from('admins').select('id').eq('id',id).single();return !!data;}

// Strong password check
function isStrongPassword(pwd){
  if(!pwd || pwd.length < 8) return 'Password must be at least 8 characters';
  if(!/[A-Z]/.test(pwd)) return 'Password must contain uppercase letter';
  if(!/[a-z]/.test(pwd)) return 'Password must contain lowercase letter';
  if(!/[0-9]/.test(pwd)) return 'Password must contain a number';
  if(!/[^A-Za-z0-9]/.test(pwd)) return 'Password must contain special character (!@#$%^&*)';
  return null;
}

app.post('/api/auth/admin-signup',async(req,res)=>{
  const{email,password,full_name}=req.body;
  if(!email||!password||!full_name) return res.status(400).json({error:'Full Name, Email and Password required'});
  const strongErr = isStrongPassword(password);
  if(strongErr) return res.status(400).json({error:strongErr});
  const{count}=await supabaseAdmin.from('admins').select('*',{count:'exact',head:true});
  if(count>=2) return res.status(400).json({error:'Maximum 2 admins reached - registration disabled'});
  const{data:au,error:ae}=await supabaseAdmin.auth.admin.createUser({email,password,email_confirm:true,user_metadata:{role:'admin',full_name}});
  if(ae) return res.status(400).json({error:ae.message});
  await supabaseAdmin.from('admins').insert({id:au.user.id,email,full_name});
  const token=jwt.sign({id:au.user.id,email,role:'admin'},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:au.user});
});

app.post('/api/auth/admin-login',async(req,res)=>{
  const{email,password}=req.body;
  const{data,error}=await supabaseAdmin.auth.signInWithPassword({email,password});
  if(error) return res.status(400).json({error:error.message});
  const{data:ad}=await supabaseAdmin.from('admins').select('*').eq('id',data.user.id).single();
  if(!ad) return res.status(403).json({error:'Not an admin account'});
  const token=jwt.sign({id:data.user.id,email,role:'admin'},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:data.user});
});

// Forgot password: admin types email, new password, repeat password, backend confirms email exists and updates password
app.post('/api/auth/forgot-password',async(req,res)=>{
  const{email,new_password,repeat_password}=req.body;
  if(!email||!new_password||!repeat_password) return res.status(400).json({error:'Email, new password and repeat password required'});
  if(new_password!==repeat_password) return res.status(400).json({error:'Passwords do not match'});
  const strongErr = isStrongPassword(new_password);
  if(strongErr) return res.status(400).json({error:strongErr});
  // Check admin exists
  const{data:adminRow}=await supabaseAdmin.from('admins').select('id,email').eq('email',email.trim().toLowerCase()).single();
  if(!adminRow) return res.status(404).json({error:'No admin account found with this email'});
  // Update password via Supabase admin API
  const{error:updateErr}=await supabaseAdmin.auth.admin.updateUserById(adminRow.id,{password:new_password});
  if(updateErr) return res.status(400).json({error:updateErr.message});
  res.json({success:true,message:'Password updated successfully - login with new password'});
});

app.post('/api/admin/admit',auth,async(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  if(!(await isAdmin(req.user.id))) return res.status(403).json({error:'Not admin'});
  const{adm_number,full_name,level,total_fees,course}=req.body;
  if(!adm_number||!full_name||!level) return res.status(400).json({error:'Admission No, Name, Year required'});
  const{data,error}=await supabaseAdmin.from('students').insert({adm_number:adm_number.trim().toUpperCase(),full_name:full_name.trim(),level:level.trim(),course:(course||level).trim(),total_fees:parseInt(total_fees)||0,paid_amount:0,is_registered:false}).select().single();
  if(error) return res.status(400).json({error:error.message});
  res.json(data);
});

app.get('/api/admin/students',auth,async(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  const{data}=await supabaseAdmin.from('students').select('*').order('created_at',{ascending:false});
  res.json(data);
});

app.post('/api/admin/add-payment',auth,async(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  const{adm_number,amount,type,method}=req.body;
  const adm=adm_number.trim().toUpperCase();
  const{data:st}=await supabaseAdmin.from('students').select('*').eq('adm_number',adm).single();
  if(!st) return res.status(404).json({error:'Student not found'});
  const np=st.paid_amount+parseInt(amount);
  await supabaseAdmin.from('students').update({paid_amount:np}).eq('adm_number',adm);
  await supabaseAdmin.from('payments').insert({adm_number:adm,student_id:st.id,amount:parseInt(amount),type:type||'fees',status:'confirmed',method:method||'admin_direct'});
  const bal=st.total_fees-np;
  await supabaseAdmin.from('notifications').insert({for_adm_number:adm,for_user_id:st.id,title:'Fees Added',message:'Your fees KES '+amount+' added balance KES '+bal+'.'});
  res.json({success:true,balance:bal});
});

app.post('/api/auth/student-signup',async(req,res)=>{
  const{adm_number,full_name,level,password}=req.body;
  if(!adm_number||!full_name||!level||!password) return res.status(400).json({error:'All required'});
  const strongErr = isStrongPassword(password);
  if(strongErr) return res.status(400).json({error:strongErr});
  const adm=adm_number.trim().toUpperCase();
  const name=full_name.trim();
  const lvl=level.trim();
  const{data:ad}=await supabaseAdmin.from('students').select('*').eq('adm_number',adm).single();
  if(!ad) return res.status(404).json({error:'Not found '+adm});
  if(ad.is_registered) return res.status(400).json({error:'Already registered'});
  if(ad.full_name.toLowerCase()!==name.toLowerCase()) return res.status(400).json({error:'Name mismatch Expected '+ad.full_name});
  if(ad.level.toLowerCase()!==lvl.toLowerCase()) return res.status(400).json({error:'Level mismatch Expected '+ad.level});
  const email=adm.toLowerCase()+'@rakti.local';
  const{data:au,error:ae}=await supabaseAdmin.auth.admin.createUser({email,password,email_confirm:true,user_metadata:{adm_number:adm,full_name:ad.full_name,level:ad.level}});
  if(ae) return res.status(400).json({error:ae.message});
  const{data:upd}=await supabaseAdmin.from('students').update({id:au.user.id,email,is_registered:true}).eq('adm_number',adm).select().single();
  await supabaseAdmin.from('notifications').insert({for_adm_number:adm,for_user_id:au.user.id,title:'Registration Successful',message:'Welcome '+ad.full_name+'! Balance KES '+upd.balance+'.'});
  const token=jwt.sign({id:au.user.id,adm_number:adm,role:'student'},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:au.user,student:upd});
});

app.post('/api/auth/student-login',async(req,res)=>{
  const{adm_number,password}=req.body;
  if(!adm_number||!password) return res.status(400).json({error:'required'});
  const adm=adm_number.trim().toUpperCase();
  const email=adm.toLowerCase()+'@rakti.local';
  const{data,error}=await supabaseAdmin.auth.signInWithPassword({email,password});
  if(error) return res.status(400).json({error:'Invalid adm or password'});
  const{data:st}=await supabaseAdmin.from('students').select('*').eq('adm_number',adm).single();
  const token=jwt.sign({id:data.user.id,adm_number:adm,role:'student'},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:data.user,student:st});
});

app.post('/api/student/submit-payment',auth,async(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const{amount,type,method}=req.body;
  const{data,error}=await supabaseAdmin.from('payments').insert({adm_number:req.user.adm_number,student_id:req.user.id,amount:parseInt(amount),type,method,status:'pending'}).select().single();
  if(error) return res.status(400).json({error:error.message});
  res.json(data);
});

app.get('/api/student/me',auth,async(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const{data:st}=await supabaseAdmin.from('students').select('*').eq('adm_number',req.user.adm_number).single();
  const{data:pay}=await supabaseAdmin.from('payments').select('*').eq('adm_number',req.user.adm_number).order('submitted_at',{ascending:false});
  const{data:notifs}=await supabaseAdmin.from('notifications').select('*').eq('for_adm_number',req.user.adm_number).order('created_at',{ascending:false}).limit(20);
  res.json({student:st,payments:pay,notifications:notifs});
});

app.get('/api/admin/pending-payments',auth,async(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  const{data,error}=await supabaseAdmin.from('payments').select('*, students(full_name,adm_number,level)').eq('status','pending').order('submitted_at',{ascending:false});
  if(error) return res.status(400).json({error:error.message});
  res.json(data);
});

app.post('/api/admin/confirm-payment',auth,async(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  const{payment_id,action}=req.body;
  const{data:pay}=await supabaseAdmin.from('payments').select('*').eq('id',payment_id).single();
  if(!pay||pay.status!=='pending') return res.status(400).json({error:'Invalid'});
  if(action==='confirmed'){
    await supabaseAdmin.from('payments').update({status:'confirmed',confirmed_at:new Date().toISOString()}).eq('id',payment_id);
    const{data:st}=await supabaseAdmin.from('students').select('*').eq('adm_number',pay.adm_number).single();
    const np=st.paid_amount+pay.amount;
    await supabaseAdmin.from('students').update({paid_amount:np}).eq('adm_number',pay.adm_number);
    const bal=st.total_fees-np;
    await supabaseAdmin.from('notifications').insert({for_adm_number:pay.adm_number,for_user_id:pay.student_id,title:'Payment Confirmed',message:'Your '+pay.type+' KES '+pay.amount+' confirmed Balance KES '+bal+'.'});
    return res.json({success:true,balance:bal});
  }else{
    await supabaseAdmin.from('payments').update({status:'rejected'}).eq('id',payment_id);
    await supabaseAdmin.from('notifications').insert({for_adm_number:pay.adm_number,for_user_id:pay.student_id,title:'Not Received',message:'Your '+pay.type+' KES '+pay.amount+' not received.'});
    return res.json({success:true});
  }
});

app.get('/api',(req,res)=>res.json({message:'Rakti backend cloud strong password + repeat + forgot email new password'}));
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.get('/student',(req,res)=>res.sendFile(path.join(__dirname,'student.html')));
const PORT=process.env.PORT||4000;
app.listen(PORT,()=>console.log('Running '+PORT+' strong password + forgot'));
