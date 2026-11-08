const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const required = ['DATABASE_URL','SESSION_SECRET','MANAGER_USERNAME','MANAGER_PASSWORD'];
for (const k of required) if (!process.env[k]) { console.error(`Missing required environment setting: ${k}`); process.exit(1); }
if (process.env.MANAGER_PASSWORD.length < 14) { console.error('MANAGER_PASSWORD must be at least 14 characters.'); process.exit(1); }
if (process.env.SESSION_SECRET.length < 32) { console.error('SESSION_SECRET must be at least 32 characters.'); process.exit(1); }
const pool = new Pool({ connectionString:process.env.DATABASE_URL, ssl:process.env.DATABASE_SSL==='false'?false:{ rejectUnauthorized:false } });
const app = express();
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy:false }));
app.use(express.json({limit:'32kb'}));
app.use(session({
  store:new PgSession({pool,tableName:'user_sessions',createTableIfMissing:true}),
  name:'ala.sid', secret:process.env.SESSION_SECRET, resave:false, saveUninitialized:false,
  cookie:{ httpOnly:true, secure:process.env.NODE_ENV==='production', sameSite:'strict', maxAge:8*60*60*1000 }
}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));
app.use('/api/auth/login',rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false}));
app.use('/api', (req,res,next)=>{ if(req.method==='GET'||req.method==='HEAD'||req.method==='OPTIONS') return next(); const origin=req.get('origin'); if(origin && origin!==`${req.protocol}://${req.get('host')}`) return res.status(403).json({error:'رفض الطلب'}); next(); });
const query=(sql,args=[])=>pool.query(sql,args);
const cleanUser=u=>({id:u.id,username:u.username,name:u.name,role:u.role,title:u.title,dept:u.department,approved:u.approved,salary:Number(u.salary),rating:u.rating,status:u.status});
const requireAuth=(req,res,next)=>req.session.user?next():res.status(401).json({error:'يرجى تسجيل الدخول'});
const requireManager=(req,res,next)=>req.session.user?.role==='manager'?next():res.status(403).json({error:'هذه الصلاحية للمدير فقط'});
const requireEmployee=(req,res,next)=>req.session.user?.role==='employee'?next():res.status(403).json({error:'هذه الصلاحية للموظف فقط'});
const audit=(actor,action,target,details={})=>query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[actor,action,target,details]);
const asyncRoute=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);

async function bootstrapManager(){
 await query(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
 const r=await query("SELECT id FROM users WHERE role='manager' LIMIT 1");
 if(!r.rowCount){ const hash=await bcrypt.hash(process.env.MANAGER_PASSWORD,12); await query("INSERT INTO users(username,password_hash,name,role,approved,title,department) VALUES($1,$2,'سامي أبو علي','manager',true,'مدير عام','الإدارة')",[process.env.MANAGER_USERNAME.trim().toLowerCase(),hash]); console.log('Initial manager created from private environment settings.'); }
 else await query("UPDATE users SET username=lower(username) WHERE role='manager' AND username<>lower(username)");
}
app.post('/api/auth/register',asyncRoute(async(req,res)=>{
 const {username,password,name,title,dept}=req.body||{};
 if(typeof name!=='string'||name.trim().length<3||name.trim().length>100||typeof username!=='string'||!/^[A-Za-z0-9_.-]{4,32}$/.test(username)||typeof password!=='string'||password.length<12||password.length>128||typeof title!=='string'||title.length>100||typeof dept!=='string'||dept.length>80) return res.status(400).json({error:'تحقق من الاسم واسم المستخدم وكلمة المرور (12 خانة على الأقل)'});
 const hash=await bcrypt.hash(password,12);
 try{ await query("INSERT INTO users(username,password_hash,name,role,title,department,approved,status) VALUES($1,$2,$3,'employee',$4,$5,false,'بانتظار التفعيل')",[username.toLowerCase(),hash,name.trim(),title.trim(),dept]); res.status(201).json({ok:true}); }
 catch(e){if(e.code==='23505') return res.status(409).json({error:'اسم المستخدم مستخدم مسبقاً'}); throw e;}
}));
app.post('/api/auth/login',asyncRoute(async(req,res)=>{
 const {username,password}=req.body||{}; if(typeof username!=='string'||typeof password!=='string') return res.status(400).json({error:'أدخل بيانات الدخول'});
 const {rows}=await query('SELECT * FROM users WHERE username=$1',[username.trim().toLowerCase()]); const u=rows[0];
 if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
 if(u.role==='employee'&&!u.approved) return res.status(403).json({error:'الحساب بانتظار تفعيل المدير'});
 await new Promise((resolve,reject)=>req.session.regenerate(e=>e?reject(e):resolve())); req.session.user={id:u.id,role:u.role}; res.json({user:cleanUser(u)});
}));
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('ala.sid');res.json({ok:true});}));
app.get('/api/me',requireAuth,asyncRoute(async(req,res)=>{const r=await query('SELECT * FROM users WHERE id=$1',[req.session.user.id]); if(!r.rowCount)return res.status(401).json({error:'انتهت الجلسة'});res.json({user:cleanUser(r.rows[0])});}));
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.get('/api/dashboard',requireAuth,asyncRoute(async(req,res)=>{
 const mgr=req.session.user.role==='manager';
 const users=await query(`SELECT u.*, a.work_date, a.clock_in, a.clock_out, m.transfers,m.exchange,m.wallets FROM users u LEFT JOIN attendance a ON a.user_id=u.id AND a.work_date=CURRENT_DATE LEFT JOIN daily_metrics m ON m.user_id=u.id AND m.work_date=CURRENT_DATE ${mgr?"WHERE u.role='employee'":"WHERE u.id=$1"} ORDER BY u.created_at`,mgr?[]:[req.session.user.id]);
 const tasks=await query(`SELECT * FROM tasks ${mgr?'':'WHERE employee_id=$1'} ORDER BY created_at DESC`,mgr?[]:[req.session.user.id]);
 const notes=mgr?await query('SELECT n.*,u.name AS employee_name FROM notifications n JOIN users u ON u.id=n.employee_id ORDER BY n.created_at DESC LIMIT 50'): {rows:[]};
 const employeeRows=users.rows.map(u=>({...cleanUser(u),attendance:{date:u.work_date||'',clockIn:u.clock_in||'',clockOut:u.clock_out||''},metrics:{transfers:u.transfers||0,exchange:u.exchange||0,wallets:u.wallets||0},tasks:tasks.rows.filter(t=>t.employee_id===u.id).map(t=>({id:t.id,title:t.title,desc:t.description,status:t.status,fileLabel:t.file_label})),files:tasks.rows.filter(t=>t.employee_id===u.id&&t.file_label).map(t=>({title:t.file_label,date:new Date(t.created_at).toISOString().slice(0,10)}))}));
 res.json({employees:employeeRows,notifications:notes.rows.map(n=>({id:n.id,empName:n.employee_name,taskTitle:n.message,time:new Date(n.created_at).toLocaleString('ar-JO')}))});
}));
app.patch('/api/manager/employees/:id',requireAuth,requireManager,asyncRoute(async(req,res)=>{
 const rating=Number(req.body?.rating),salary=Number(req.body?.salary); if(!Number.isInteger(rating)||rating<0||rating>100||!Number.isFinite(salary)||salary<0||salary>100000000)return res.status(400).json({error:'تحقق من التقييم والراتب'});
 const r=await query("UPDATE users SET rating=$1,salary=$2 WHERE id=$3 AND role='employee' RETURNING id",[rating,salary,req.params.id]); if(!r.rowCount)return res.status(404).json({error:'الموظف غير موجود'}); await audit(req.session.user.id,'employee_updated',r.rows[0].id,{rating,salary});res.json({ok:true});
}));
app.post('/api/manager/tasks',requireAuth,requireManager,asyncRoute(async(req,res)=>{
 const {employeeId,title,description='',fileLabel=''}=req.body||{}; if(!employeeId||typeof title!=='string'||title.trim().length<2||title.length>160||typeof description!=='string'||description.length>3000||typeof fileLabel!=='string'||fileLabel.length>300)return res.status(400).json({error:'تحقق من بيانات المهمة'});
 const u=await query("SELECT id FROM users WHERE id=$1 AND role='employee' AND approved=true",[employeeId]);if(!u.rowCount)return res.status(404).json({error:'الموظف غير موجود أو غير مفعل'});
 await query('INSERT INTO tasks(employee_id,title,description,file_label) VALUES($1,$2,$3,$4)',[employeeId,title.trim(),description.trim(),fileLabel.trim()]);await audit(req.session.user.id,'task_assigned',employeeId,{title:title.trim()});res.status(201).json({ok:true});
}));
app.post('/api/manager/employees/:id/approve',requireAuth,requireManager,asyncRoute(async(req,res)=>{const r=await query("UPDATE users SET approved=true,status='على رأس العمل' WHERE id=$1 AND role='employee' RETURNING id",[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'الحساب غير موجود'});await audit(req.session.user.id,'employee_approved',req.params.id);res.json({ok:true});}));
app.post('/api/employee/tasks/:id/complete',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{const r=await query("UPDATE tasks SET status='completed',completed_at=now() WHERE id=$1 AND employee_id=$2 AND status='pending' RETURNING id,title",[req.params.id,req.session.user.id]);if(!r.rowCount)return res.status(404).json({error:'المهمة غير موجودة أو مكتملة'});await query('INSERT INTO notifications(employee_id,task_id,message) VALUES($1,$2,$3)',[req.session.user.id,r.rows[0].id,`أتم المهمة: ${r.rows[0].title}`]);await audit(req.session.user.id,'task_completed',r.rows[0].id);res.json({ok:true});}));
app.post('/api/employee/attendance/:action',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{
 const action=req.params.action; if(!['in','out'].includes(action))return res.status(404).json({error:'غير موجود'});
 if(action==='in'){await query('INSERT INTO attendance(user_id,work_date,clock_in) VALUES($1,CURRENT_DATE,now()) ON CONFLICT(user_id,work_date) DO NOTHING',[req.session.user.id]);await query("UPDATE users SET status='على رأس العمل' WHERE id=$1",[req.session.user.id]);}
 else {const r=await query('UPDATE attendance SET clock_out=now() WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL RETURNING id',[req.session.user.id]);if(!r.rowCount)return res.status(409).json({error:'لا يوجد حضور نشط لتسجيل الانصراف'});await query("UPDATE users SET status='انتهى الدوام' WHERE id=$1",[req.session.user.id]);}
 await audit(req.session.user.id,`attendance_${action}`,req.session.user.id);res.json({ok:true});
}));
app.post('/api/employee/status',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{const status=req.body?.status;if(!['على رأس العمل','في اجتماع','في استراحة'].includes(status))return res.status(400).json({error:'حالة غير صالحة'});const a=await query('SELECT id FROM attendance WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL',[req.session.user.id]);if(!a.rowCount)return res.status(409).json({error:'سجل الحضور أولاً'});await query('UPDATE users SET status=$1 WHERE id=$2',[status,req.session.user.id]);await audit(req.session.user.id,'status_changed',req.session.user.id,{status});res.json({ok:true});}));
app.post('/api/employee/metrics',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{const {transfers,exchange,wallets}=req.body||{};for(const n of [transfers,exchange,wallets])if(!Number.isInteger(n)||n<0||n>100000)return res.status(400).json({error:'أدخل أعداداً صحيحة غير سالبة'});await query('INSERT INTO daily_metrics(user_id,work_date,transfers,exchange,wallets) VALUES($1,CURRENT_DATE,$2,$3,$4) ON CONFLICT(user_id,work_date) DO UPDATE SET transfers=EXCLUDED.transfers,exchange=EXCLUDED.exchange,wallets=EXCLUDED.wallets',[req.session.user.id,transfers,exchange,wallets]);res.json({ok:true});}));
app.use(express.static(path.join(__dirname),{index:'index.html',dotfiles:'deny'}));
app.use((err,req,res,next)=>{console.error(err.message);res.status(500).json({error:'حدث خطأ في الخادم'});});
const port=Number(process.env.PORT||3000);
bootstrapManager().then(()=>app.listen(port,()=>console.log(`Staff portal listening on ${port}`))).catch(e=>{console.error('Startup failed:',e.message);process.exit(1);});
