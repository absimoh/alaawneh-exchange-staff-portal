const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const required = ['DATABASE_URL','SESSION_SECRET','MANAGER_USERNAME','MANAGER_PASSWORD'];
for (const k of required) if (!process.env[k]) { console.error(`Missing required environment setting: ${k}`); process.exit(1); }
if (process.env.MANAGER_PASSWORD.length < 14) { console.error('MANAGER_PASSWORD must be at least 14 characters.'); process.exit(1); }
if (process.env.SESSION_SECRET.length < 32) { console.error('SESSION_SECRET must be at least 32 characters.'); process.exit(1); }
const pool = new Pool({ connectionString:process.env.DATABASE_URL, ssl:process.env.DATABASE_SSL==='false'?false:{ rejectUnauthorized:false } });
pool.on('connect',client=>client.query("SET TIME ZONE 'Asia/Amman'"));
const app = express();
app.disable('x-powered-by'); app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy:false }));
app.use(express.json({limit:'32kb'}));
const acceptedTaskFiles=new Set(['application/pdf','image/jpeg','image/png','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']);
const taskFileUpload=multer({storage:multer.memoryStorage(),limits:{fileSize:5*1024*1024,files:1,fields:4,parts:5,fieldSize:3500},fileFilter:(req,file,done)=>acceptedTaskFiles.has(file.mimetype)?done(null,true):done(new Error('الملف غير مدعوم. استخدم PDF أو DOCX أو XLSX أو صورة PNG/JPEG.'))});
app.use(session({
  store:new PgSession({pool,tableName:'user_sessions',createTableIfMissing:true}),
  name:'ala.sid', secret:process.env.SESSION_SECRET, resave:false, saveUninitialized:false,
  cookie:{ httpOnly:true, secure:process.env.NODE_ENV==='production', sameSite:'strict', maxAge:8*60*60*1000 }
}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));
app.use('/api/auth/login',rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false}));
const taskUploadLimiter=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false});
app.use('/api', (req,res,next)=>{ if(req.method==='GET'||req.method==='HEAD'||req.method==='OPTIONS') return next(); const origin=req.get('origin'); if(origin && origin!==`${req.protocol}://${req.get('host')}`) return res.status(403).json({error:'رفض الطلب'}); next(); });
const query=(sql,args=[])=>pool.query(sql,args);
const transaction=async fn=>{const client=await pool.connect();try{await client.query('BEGIN');const result=await fn(client);await client.query('COMMIT');return result;}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}};
const localClock=value=>value?new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Amman',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date(value)):'';
const cleanUser=u=>({id:u.id,username:u.username,name:u.name,role:u.role,title:u.title,dept:u.department,approved:u.approved,disabled:u.disabled,salary:Number(u.salary),rating:u.rating,status:u.status});
const requireAuth=async(req,res,next)=>{if(!req.session.user)return res.status(401).json({error:'يرجى تسجيل الدخول'});const {rows}=await query('SELECT role,disabled FROM users WHERE id=$1',[req.session.user.id]);if(!rows[0]||(rows[0].role==='employee'&&rows[0].disabled)){req.session.destroy(()=>{});return res.status(401).json({error:'الحساب موقوف'});}next();};
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
 if(!u||u.disabled||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
 if(u.role==='employee'&&!u.approved) return res.status(403).json({error:'الحساب بانتظار تفعيل المدير'});
 await new Promise((resolve,reject)=>req.session.regenerate(e=>e?reject(e):resolve())); req.session.user={id:u.id,role:u.role}; res.json({user:cleanUser(u)});
}));
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('ala.sid');res.json({ok:true});}));
app.get('/api/me',requireAuth,asyncRoute(async(req,res)=>{const r=await query('SELECT * FROM users WHERE id=$1',[req.session.user.id]); if(!r.rowCount)return res.status(401).json({error:'انتهت الجلسة'});res.json({user:cleanUser(r.rows[0])});}));
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.get('/api/dashboard',requireAuth,asyncRoute(async(req,res)=>{
 const mgr=req.session.user.role==='manager';
 const expired=await query("UPDATE attendance_sessions SET clock_out=now() WHERE clock_in IS NOT NULL AND clock_out IS NULL AND last_seen < now()-interval '2 minutes' RETURNING user_id");
 if(expired.rowCount){const ids=expired.rows.map(r=>r.user_id);await query("UPDATE users SET status='انتهى الدوام' WHERE id=ANY($1::uuid[])",[ids]);await query("INSERT INTO audit_log(actor_id,action,target_id,details) SELECT NULL,'attendance_auto_out',user_id,'{\"reason\":\"inactive_session\"}'::jsonb FROM unnest($1::uuid[]) AS expired_ids(user_id)",[ids]);}
 if(!mgr)await query('UPDATE attendance_sessions SET last_seen=now() WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL',[req.session.user.id]);
 const users=await query(`SELECT u.*, a.work_date, a.clock_in, a.clock_out, a.worked_seconds FROM users u LEFT JOIN LATERAL (SELECT MAX(work_date) AS work_date,(array_agg(clock_in ORDER BY clock_in DESC))[1] AS clock_in,(array_agg(clock_out ORDER BY clock_in DESC))[1] AS clock_out,COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out,now())-clock_in))),0)::bigint AS worked_seconds FROM attendance_sessions WHERE user_id=u.id AND work_date=CURRENT_DATE) a ON true ${mgr?"WHERE u.role='employee' AND u.disabled=false":"WHERE u.id=$1 AND u.disabled=false"} ORDER BY u.created_at`,mgr?[]:[req.session.user.id]);
 const counts=await query(`SELECT employee_id,COUNT(*) FILTER(WHERE operation_type='تحويل أموال')::int AS transfers,COUNT(*) FILTER(WHERE operation_type='تصريف عملات')::int AS exchange,COUNT(*) FILTER(WHERE operation_type='محافظ إلكترونية')::int AS wallets FROM operations WHERE created_at::date=CURRENT_DATE ${mgr?'':'AND employee_id=$1'} GROUP BY employee_id`,mgr?[]:[req.session.user.id]);
 const countByEmployee=new Map(counts.rows.map(r=>[r.employee_id,r]));
 const tasks=await query(`SELECT * FROM tasks ${mgr?'':'WHERE employee_id=$1'} ORDER BY created_at DESC`,mgr?[]:[req.session.user.id]);
 const notes=mgr?await query('SELECT n.*,u.name AS employee_name,COALESCE(t.title,n.message) AS task_title FROM notifications n JOIN users u ON u.id=n.employee_id LEFT JOIN tasks t ON t.id=n.task_id ORDER BY n.created_at DESC LIMIT 50'): {rows:[]};
 const logs=mgr?await query('SELECT l.action,l.created_at,actor.name AS actor_name,target.name AS target_name FROM audit_log l LEFT JOIN users actor ON actor.id=l.actor_id LEFT JOIN users target ON target.id=l.target_id ORDER BY l.created_at DESC LIMIT 100'): {rows:[]};
 const ops=await query(`SELECT o.*,u.name AS employee_name FROM operations o JOIN users u ON u.id=o.employee_id ${mgr?'':'WHERE o.employee_id=$1'} ORDER BY o.created_at DESC LIMIT ${mgr?'200':'30'}`,mgr?[]:[req.session.user.id]);
 const employeeRows=users.rows.map(u=>{const c=countByEmployee.get(u.id)||{};return {...cleanUser(u),attendance:{date:u.work_date||'',clockIn:localClock(u.clock_in),clockOut:localClock(u.clock_out),workedSeconds:Number(u.worked_seconds||0)},metrics:{transfers:c.transfers||0,exchange:c.exchange||0,wallets:c.wallets||0},tasks:tasks.rows.filter(t=>t.employee_id===u.id).map(t=>({id:t.id,title:t.title,desc:t.description,status:t.status,fileLabel:t.file_label,fileName:t.file_name,fileMime:t.file_mime})),files:tasks.rows.filter(t=>t.employee_id===u.id&&(t.file_label||t.file_data)).map(t=>{let url=null;try{const parsed=new URL(t.file_label);if(parsed.protocol==='https:')url=parsed.toString();}catch{}return {id:t.id,title:t.file_name||t.file_label,url,downloadUrl:t.file_mime?`/api/tasks/${t.id}/file`:null,date:new Date(t.created_at).toLocaleDateString('en-CA',{timeZone:'Asia/Amman'})};})};});
 res.json({employees:employeeRows,operations:ops.rows.map(o=>({id:o.id,employeeId:o.employee_id,employeeName:o.employee_name,type:o.operation_type,amount:Number(o.amount),currencyFrom:o.currency_from,resultAmount:Number(o.result_amount),currencyTo:o.currency_to,exchangeRate:Number(o.amount)>0?Number(o.result_amount)/Number(o.amount):0,referenceCode:o.reference_code,note:o.note,createdAt:o.created_at.toLocaleDateString('en-CA',{timeZone:'Asia/Amman'}),time:o.created_at.toLocaleString('ar-JO',{timeZone:'Asia/Amman'})})),notifications:notes.rows.map(n=>({id:n.id,empName:n.employee_name,taskTitle:n.task_title,time:n.created_at.toLocaleString('ar-JO',{timeZone:'Asia/Amman'})})),audit:logs.rows.map(l=>({action:l.action,actor:l.actor_name||'النظام',target:l.target_name||'',time:l.created_at.toLocaleString('ar-JO',{timeZone:'Asia/Amman'})}))});
}));
app.post('/api/employee/operations',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{
 const {type,amount,currencyFrom,resultAmount,currencyTo,referenceCode='',note=''}=req.body||{};
 const currencies=['JOD','USD','SAR','AED','EUR']; const types=['تحويل أموال','تصريف عملات','محافظ إلكترونية'];
 if(!types.includes(type)||!Number.isFinite(Number(amount))||Number(amount)<=0||Number(amount)>100000000||!Number.isFinite(Number(resultAmount))||Number(resultAmount)<=0||Number(resultAmount)>100000000||!currencies.includes(currencyFrom)||!currencies.includes(currencyTo)||typeof referenceCode!=='string'||referenceCode.length>40||typeof note!=='string'||note.length>250)return res.status(400).json({error:'تحقق من بيانات العملية'});
 const attendance=await query('SELECT id FROM attendance_sessions WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL',[req.session.user.id]);if(!attendance.rowCount)return res.status(409).json({error:'سجّل الحضور قبل إضافة عملية'});
 const exchangeRate=Number(resultAmount)/Number(amount);
 await transaction(async client=>{const r=await client.query('INSERT INTO operations(employee_id,operation_type,amount,currency_from,result_amount,currency_to,exchange_rate,reference_code,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',[req.session.user.id,type,Number(amount),currencyFrom,Number(resultAmount),currencyTo,exchangeRate,referenceCode.trim(),note.trim()]);await client.query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.user.id,'operation_recorded',r.rows[0].id,{type,amount:Number(amount),currencyFrom,currencyTo,exchangeRate}]);});res.status(201).json({ok:true});
}));
app.patch('/api/manager/employees/:id',requireAuth,requireManager,asyncRoute(async(req,res)=>{
 const rating=Number(req.body?.rating),salary=Number(req.body?.salary); if(!Number.isInteger(rating)||rating<0||rating>100||!Number.isFinite(salary)||salary<0||salary>100000000)return res.status(400).json({error:'تحقق من التقييم والراتب'});
 const r=await transaction(async client=>{const updated=await client.query("UPDATE users SET rating=$1,salary=$2 WHERE id=$3 AND role='employee' AND disabled=false RETURNING id",[rating,salary,req.params.id]);if(updated.rowCount)await client.query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.user.id,'employee_updated',updated.rows[0].id,{rating,salary}]);return updated;}); if(!r.rowCount)return res.status(404).json({error:'الموظف غير موجود'});res.json({ok:true});
}));
app.post('/api/manager/tasks',requireAuth,requireManager,taskUploadLimiter,taskFileUpload.single('file'),asyncRoute(async(req,res)=>{
 const {employeeId,title,description='',fileLabel=''}=req.body||{};const file=req.file;
 if(!employeeId||typeof title!=='string'||title.trim().length<2||title.length>160||typeof description!=='string'||description.length>3000||typeof fileLabel!=='string'||fileLabel.length>300||(!file&&fileLabel.trim().startsWith('http')&&!/^https:\/\//i.test(fileLabel.trim())))return res.status(400).json({error:'تحقق من بيانات المهمة والرابط (يجب أن يبدأ HTTPS)'});
 if(file&&fileLabel.trim())return res.status(400).json({error:'اختر رفع ملف أو إضافة رابط خارجي، وليس الاثنين معاً'});
 const safeName=file?path.basename(file.originalname).replace(/[\\/\r\n\"\u0000-\u001f]/g,'_').slice(0,180):'';
 const sig=file?.buffer||Buffer.alloc(0);if(file){const mime=file.mimetype,ext=path.extname(file.originalname).toLowerCase();const expectedExt=mime==='application/pdf'?['.pdf']:mime==='image/png'?['.png']:mime==='image/jpeg'?['.jpg','.jpeg']:mime==='application/vnd.openxmlformats-officedocument.wordprocessingml.document'?['.docx']:['.xlsx'];const valid=expectedExt.includes(ext)&&(mime==='application/pdf'?sig.subarray(0,5).toString()==='%PDF-':mime==='image/png'?sig.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):mime==='image/jpeg'?sig[0]===255&&sig[1]===216&&sig[2]===255:(sig[0]===80&&sig[1]===75));if(!valid)return res.status(400).json({error:'محتوى الملف أو امتداده لا يطابق نوعه'});}
 const created=await transaction(async client=>{const r=await client.query("INSERT INTO tasks(employee_id,title,description,file_label,file_data,file_mime,file_name) SELECT id,$2,$3,$4,$5,$6,$7 FROM users WHERE id=$1 AND role='employee' AND approved=true AND disabled=false RETURNING id",[employeeId,title.trim(),description.trim(),file?'':fileLabel.trim(),file?.buffer||null,file?.mimetype||null,safeName]);if(r.rowCount)await client.query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.user.id,'task_assigned',employeeId,{title:title.trim(),attachment:!!file}]);return r;});if(!created.rowCount)return res.status(404).json({error:'الموظف غير موجود أو غير مفعل'});res.status(201).json({ok:true});
}));
app.get('/api/tasks/:id/file',requireAuth,asyncRoute(async(req,res)=>{
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.id))return res.status(404).json({error:'الملف غير موجود'});
 const {rows}=await query('SELECT employee_id,file_data,file_mime,file_name FROM tasks WHERE id=$1 AND file_data IS NOT NULL',[req.params.id]);const file=rows[0];if(!file)return res.status(404).json({error:'الملف غير موجود'});
 if(req.session.user.role!=='manager'&&req.session.user.id!==file.employee_id)return res.status(403).json({error:'لا تملك صلاحية تنزيل هذا الملف'});
 const name=String(file.file_name||'attachment').replace(/[\r\n\"\\]/g,'_');res.set({'Content-Type':file.file_mime,'Content-Disposition':`attachment; filename="attachment"; filename*=UTF-8''${encodeURIComponent(name)}`,'Content-Length':file.file_data.length,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}).send(file.file_data);
}));
app.post('/api/manager/employees/:id/approve',requireAuth,requireManager,asyncRoute(async(req,res)=>{const r=await transaction(async client=>{const updated=await client.query("UPDATE users SET approved=true,status='لم يسجل الحضور' WHERE id=$1 AND role='employee' AND disabled=false AND approved=false RETURNING id",[req.params.id]);if(updated.rowCount)await client.query('INSERT INTO audit_log(actor_id,action,target_id) VALUES($1,$2,$3)',[req.session.user.id,'employee_approved',req.params.id]);return updated;});if(!r.rowCount)return res.status(404).json({error:'الحساب غير موجود أو مفعل مسبقاً'});res.json({ok:true});}));
app.delete('/api/manager/employees/:id',requireAuth,requireManager,asyncRoute(async(req,res)=>{const r=await transaction(async client=>{const updated=await client.query("UPDATE users SET disabled=true,approved=false,status='مؤرشف' WHERE id=$1 AND role='employee' AND disabled=false RETURNING id",[req.params.id]);if(updated.rowCount)await client.query('INSERT INTO audit_log(actor_id,action,target_id) VALUES($1,$2,$3)',[req.session.user.id,'employee_archived',req.params.id]);return updated;});if(!r.rowCount)return res.status(404).json({error:'الموظف غير موجود أو مؤرشف مسبقاً'});res.json({ok:true});}));
app.post('/api/employee/tasks/:id/complete',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{const r=await transaction(async client=>{const updated=await client.query("UPDATE tasks SET status='completed',completed_at=now() WHERE id=$1 AND employee_id=$2 AND status='pending' RETURNING id,title",[req.params.id,req.session.user.id]);if(updated.rowCount){await client.query('INSERT INTO notifications(employee_id,task_id,message) VALUES($1,$2,$3)',[req.session.user.id,updated.rows[0].id,`أتم المهمة: ${updated.rows[0].title}`]);await client.query('INSERT INTO audit_log(actor_id,action,target_id) VALUES($1,$2,$3)',[req.session.user.id,'task_completed',updated.rows[0].id]);}return updated;});if(!r.rowCount)return res.status(404).json({error:'المهمة غير موجودة أو مكتملة'});res.json({ok:true});}));
app.post('/api/employee/attendance/auto-out',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{await transaction(async client=>{const ended=await client.query('UPDATE attendance_sessions SET clock_out=now() WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL RETURNING id',[req.session.user.id]);if(ended.rowCount){await client.query("UPDATE users SET status='انتهى الدوام' WHERE id=$1",[req.session.user.id]);await client.query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.user.id,'attendance_auto_out',req.session.user.id,{reason:'browser_exit'}]);}});res.json({ok:true});}));
app.post('/api/employee/attendance/:action',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{
 const action=req.params.action; if(!['in','out'].includes(action))return res.status(404).json({error:'غير موجود'});
 const result=await transaction(async client=>{const r=action==='in'?await client.query('INSERT INTO attendance_sessions(user_id,work_date,clock_in,last_seen) VALUES($1,CURRENT_DATE,now(),now()) ON CONFLICT(user_id,work_date) WHERE clock_out IS NULL DO NOTHING RETURNING id',[req.session.user.id]):await client.query('UPDATE attendance_sessions SET clock_out=now() WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL RETURNING id',[req.session.user.id]);if(r.rowCount){await client.query('UPDATE users SET status=$1 WHERE id=$2',[action==='in'?'على رأس العمل':'انتهى الدوام',req.session.user.id]);await client.query('INSERT INTO audit_log(actor_id,action,target_id) VALUES($1,$2,$3)',[req.session.user.id,`attendance_${action}`,req.session.user.id]);}return r;});if(!result.rowCount)return res.status(409).json({error:action==='in'?'دوامك مسجل حالياً أو تعذر تسجيل الحضور':'لا يوجد حضور نشط لتسجيل الانصراف'});res.json({ok:true});
}));
app.post('/api/employee/status',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{
 const status=req.body?.status;if(!['على رأس العمل','في اجتماع','في استراحة'].includes(status))return res.status(400).json({error:'حالة غير صالحة'});
 const changed=await transaction(async client=>{const a=await client.query('SELECT id FROM attendance_sessions WHERE user_id=$1 AND work_date=CURRENT_DATE AND clock_in IS NOT NULL AND clock_out IS NULL FOR UPDATE',[req.session.user.id]);if(!a.rowCount)return false;await client.query('UPDATE users SET status=$1 WHERE id=$2',[status,req.session.user.id]);await client.query('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.user.id,'status_changed',req.session.user.id,{status}]);return true;});
 if(!changed)return res.status(409).json({error:'سجل الحضور أولاً'});res.json({ok:true});
}));
app.post('/api/employee/metrics',requireAuth,requireEmployee,asyncRoute(async(req,res)=>{const {transfers,exchange,wallets}=req.body||{};for(const n of [transfers,exchange,wallets])if(!Number.isInteger(n)||n<0||n>100000)return res.status(400).json({error:'أدخل أعداداً صحيحة غير سالبة'});await query('INSERT INTO daily_metrics(user_id,work_date,transfers,exchange,wallets) VALUES($1,CURRENT_DATE,$2,$3,$4) ON CONFLICT(user_id,work_date) DO UPDATE SET transfers=EXCLUDED.transfers,exchange=EXCLUDED.exchange,wallets=EXCLUDED.wallets',[req.session.user.id,transfers,exchange,wallets]);res.json({ok:true});}));
app.use(express.static(path.join(__dirname),{index:'index.html',dotfiles:'deny'}));
app.use((err,req,res,next)=>{if(err instanceof multer.MulterError){const message=err.code==='LIMIT_FILE_SIZE'?'الحد الأقصى لحجم الملف 5 ميغابايت.':'تعذر استقبال الملف';return res.status(400).json({error:message});}if(err.message?.startsWith('الملف غير مدعوم'))return res.status(400).json({error:err.message});console.error(err.message);res.status(500).json({error:'حدث خطأ في الخادم'});});
const port=Number(process.env.PORT||3000);
bootstrapManager().then(()=>app.listen(port,()=>console.log(`Staff portal listening on ${port}`))).catch(e=>{console.error('Startup failed:',e.message);process.exit(1);});
