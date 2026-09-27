const {spawn}=require('node:child_process');
const fs=require('node:fs'),path=require('node:path');
const python=path.join(__dirname,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
if(!fs.existsSync(python)){console.error('Python environment missing. Run start.py (or see README.md) to install the backend.');process.exit(1)}
const child=spawn(python,[path.join(__dirname,'service.py'),'--port',process.env.PORT||'4173'],{cwd:__dirname,stdio:'inherit',windowsHide:true});
child.on('error',error=>{console.error(error.message);process.exitCode=1});
child.on('exit',code=>process.exit(code??0));
process.on('SIGINT',()=>child.kill('SIGINT'));
process.on('SIGTERM',()=>child.kill('SIGTERM'));
