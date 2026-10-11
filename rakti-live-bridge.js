
// This bridge connects your original HTML (which used localStorage) to your live Render backend
// It does NOT redesign your UI - it just makes save/load call the API as well
const API = window.RAKTI_API;

function getToken(isAdmin=true){
  return localStorage.getItem(isAdmin ? 'rakti_admin_token' : 'rakti_student_token') || localStorage.getItem('token');
}

// Intercept: When your original admin code admits a student (saves to rakti_students), also call live API
// We watch localStorage changes and sync to server

// ADMIN: Admit function wrapper
window.raktiAdmitToServer = async function(adm_number, full_name, level, total_fees){
  const token = getToken(true);
  if(!token) return {error:'Not logged in as admin'};
  const res = await fetch(`${API}/admin/admit`, {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body: JSON.stringify({adm_number, full_name, level, total_fees})
  });
  return await res.json();
};

// Pull live students to keep your original UI updated
window.raktiPullStudents = async function(){
  const token = getToken(true);
  if(!token) return;
  try{
    const res = await fetch(`${API}/admin/students`, {headers:{'Authorization':'Bearer '+token}});
    if(res.ok){
      const students = await res.json();
      // Convert to your original localStorage format so your original HTML tables still work
      const oldFormat = students.map(s=>({
        id: s.adm_number,
        admNo: s.adm_number,
        adm_number: s.adm_number,
        name: s.full_name,
        full_name: s.full_name,
        level: s.level,
        course: s.level,
        totalFees: s.total_fees,
        total_fees: s.total_fees,
        paid: s.paid_amount,
        paid_amount: s.paid_amount,
        balance: s.balance,
        isRegistered: s.is_registered
      }));
      localStorage.setItem('rakti_students', JSON.stringify(oldFormat));
      window.dispatchEvent(new Event('storage'));
    }
  }catch(e){ console.log('pull students failed', e); }
};

// Student: login/signup wrapper for your original HTML
window.raktiStudentLogin = async function(adm_number, password){
  const res = await fetch(`${API}/auth/student-login`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({adm_number, password})
  });
  const data = await res.json();
  if(!data.error){
    localStorage.setItem('rakti_student_token', data.token);
    localStorage.setItem('token', data.token);
  }
  return data;
};

window.raktiStudentSignup = async function(adm_number, full_name, level, password){
  const res = await fetch(`${API}/auth/student-signup`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({adm_number, full_name, level, password})
  });
  const data = await res.json();
  if(!data.error){
    localStorage.setItem('rakti_student_token', data.token);
    localStorage.setItem('token', data.token);
  }
  return data;
};

// Auto pull every 5 seconds to keep your original UI in sync with live DB
setInterval(()=>{
  const adminToken = localStorage.getItem('rakti_admin_token') || localStorage.getItem('token');
  if(adminToken){
    try{
      const payload = JSON.parse(atob(adminToken.split('.')[1]));
      if(payload.role==='admin') window.raktiPullStudents();
    }catch(e){}
  }
}, 5000);

console.log('Rakti live bridge loaded - original HTMLs now talk to', API);
