"""
WINTERMUTE C2 PROTOCOL // v9.0
- io import added
- password redaction everywhere (logger + channel output)
- safe non-interactive sudo (-n)
- robust handling of discord interactions vs messages (no permanent "thinking")
- guaranteed response paths (uses followup when interaction deferred)
- PTY echo disabled, safe buffer flushing, large-output handling via files
- safer process lifecycle management
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
import tty
import io

# =====================================================
# [ SYSTEM CONFIGURATION ]
# =====================================================

CONFIG = {
    "TOKEN": "000000000000000000",
    "ADMIN_ID": 000000000000000000,
    "GUILD_ID": 000000000000000000,
    "PREFIX": "/",
    "CATEGORY_ID": None
}

# =====================================================
# [ GLOBAL STATE ]
# =====================================================

ACTIVE_SESSIONS = {}
SESSION_BUFFERS = {}
SUDO_PASSWORD = None
CURRENT_SIMPLE_PROCESS = None

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

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def strip_ansi(text: str) -> str:
    return ansi_escape.sub('', text)

def _redact(text: str) -> str:
    global SUDO_PASSWORD
    if not text or not SUDO_PASSWORD:
        return text
    try:
        return re.sub(re.escape(SUDO_PASSWORD), "[HIDDEN]", text)
    except Exception:
        return text.replace(SUDO_PASSWORD, "[HIDDEN]")

def log(tag, message, color=GREEN):
    safe_msg = _redact(str(message))
    print(f"{DIM}[{timestamp()}]{RESET} {color}[{tag}]{RESET} {safe_msg}")

def boot_sequence():
    os.system('clear') if os.name == 'posix' else os.system('cls')
    print(f"{CYAN}{BOLD}")
    print(r"""
 █     █░ ██▓ ███▄    █ ▄▄▄█████▓▓█████  ██▀███   ███▄ ▄███▓ █    ██ ▄▄▄█████▓▓█████ 
▓█░ █ ░█░▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒ ██  ▓██▒▓  ██▒ ▓▒▓█   ▀ 
▒█░ █ ░█ ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒▓██    ▓██░▓██  ▒██░▒ ▓██░ ▒░▒███   
░█░ █ ░█ ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ ▓▓█  ░██░░ ▓██▓ ░ ▒▓█  ▄ 
░░██▒██▓ ░██░▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██▒   ░██▒▒▒█████▓   ▒██▒ ░ ░▒████▒
░ ▓░▒ ▒  ░▓  ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▒▓▒ ▒ ▒   ▒ ░░   ░░ ▒░ ░
  ▒ ░ ░   ▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░░  ░      ░░░▒░ ░ ░     ░     ░ ░  ░
    ░     ░           ░             ░  ░   ░            ░      ░                 ░  ░
    """)
    print(f"{RESET}")
    print(f"{RED}        >>> WINTERMUTE v9.0 // POLISHED <<<{RESET}\n")

# =====================================================
# [ BOT LOGIC ]
# =====================================================

intents = discord.Intents.default()
intents.message_content = True
intents.dm_messages = True
intents.guilds = True

bot = commands.Bot(command_prefix=CONFIG["PREFIX"], intents=intents, help_command=None)

# -----------------------------------------------------
# UTILS: Unified respond helper
# -----------------------------------------------------
async def respond(ctx, content: str = None, file: discord.File = None, ephemeral: bool = False):
    """
    Send a reply that works for both message-context and interaction-context.
    If interaction was deferred, use followup. Otherwise use send/reply.
    """
    # prefer followup for interactions (works if deferred)
    if getattr(ctx, "interaction", None) is not None:
        try:
            # If followup exists (after defer) this will be used; ephemeral only applies to interactions
            await ctx.followup.send(content=content, file=file, ephemeral=ephemeral)
            return
        except Exception:
            # fallthrough to other methods
            pass

    # fallback: try reply if available, else send
    try:
        await ctx.reply(content, file=file)
    except Exception:
        await ctx.send(content, file=file)

# -----------------------------------------------------
# PTY CORE
# -----------------------------------------------------

def read_from_pty(fd, channel_id):
    try:
        data = os.read(fd, 1024)
        if not data:
            return
        if channel_id in SESSION_BUFFERS:
            SESSION_BUFFERS[channel_id].extend(data)
    except OSError:
        pass

async def buffer_flusher():
    await bot.wait_until_ready()
    while not bot.is_closed():
        if SESSION_BUFFERS:
            for cid in list(SESSION_BUFFERS.keys()):
                buf = SESSION_BUFFERS[cid]
                if buf:
                    raw_text = buf.decode('utf-8', errors='ignore')
                    clean_text = strip_ansi(raw_text)
                    clean_text = _redact(clean_text)

                    SESSION_BUFFERS[cid] = bytearray()
                    channel = bot.get_channel(cid)
                    if channel:
                        try:
                            if len(clean_text) > 1900:
                                # split into chunks safe for Discord
                                for i in range(0, len(clean_text), 1900):
                                    try:
                                        channel.send(f"```bash\n{clean_text[i:i+1900]}\n```")
                                    except Exception:
                                        pass
                            else:
                                try:
                                    channel.send(f"```bash\n{clean_text}\n```")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    else:
                        close_session_internal(cid)
        await asyncio.sleep(1.0)

def close_session_internal(channel_id):
    if channel_id in ACTIVE_SESSIONS:
        s = ACTIVE_SESSIONS[channel_id]
        pid = getattr(s["proc"], "pid", "unknown")
        try:
            loop = asyncio.get_running_loop()
            try:
                loop.remove_reader(s["fd"])
            except Exception:
                pass
            try:
                os.close(s["fd"])
            except Exception:
                pass
            try:
                s["proc"].terminate()
            except Exception:
                pass
            log("TERM", f"PID {pid} terminated (Channel: {channel_id})", YELLOW)
        except Exception as e:
            log("ERR", f"Failed to term PID {pid}: {e}", RED)
        del ACTIVE_SESSIONS[channel_id]
    if channel_id in SESSION_BUFFERS:
        del SESSION_BUFFERS[channel_id]

# -----------------------------------------------------
# EVENTS
# -----------------------------------------------------

@bot.event
async def on_ready():
    boot_sequence()
    log("STATUS", f"Identity: {bot.user}", MAGENTA)

    if CONFIG["GUILD_ID"]:
        try:
            guild = discord.Object(id=CONFIG["GUILD_ID"])
            bot.tree.copy_global_to(guild=guild)
            synced = await bot.tree.sync(guild=guild)
            log("SYNC", f"Guild Commands Synced: {len(synced)}", BLUE)
            bot.tree.clear_commands(guild=None)
            await bot.tree.sync(guild=None)
            log("CLEAN", "Global cache cleared.", YELLOW)
        except Exception as e:
            log("ERR", f"Sync: {e}", RED)
    else:
        log("WARN", "GUILD_ID missing!", RED)

    bot.loop.create_task(buffer_flusher())
    await bot.change_presence(status=discord.Status.online, activity=discord.Activity(type=discord.ActivityType.listening, name="root instructions"))

def check_access(ctx): return ctx.author.id == CONFIG["ADMIN_ID"]

async def confirm_action(ctx, action):
    log("AUTH", f"Confirmation requested: {action}", YELLOW)
    msg_txt = f"```css\n[ CONFIRM: {action} (Y/N)? ]\n```"
    # send prompt via respond so it works for both contexts
    await respond(ctx, msg_txt)
    def check(m): return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() in ['y', 'yes']
    try:
        msg = await bot.wait_for('message', check=check, timeout=15.0)
        try:
            await msg.delete()
        except Exception:
            pass
        log("AUTH", f"Action {action} CONFIRMED", GREEN)
        return True
    except Exception:
        log("AUTH", f"Action {action} TIMED OUT", RED)
        try:
            await respond(ctx, "```diff\n- TIMEOUT\n```")
        except Exception:
            pass
        return False

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    if message.content.startswith(CONFIG["PREFIX"]) or message.content.startswith("!"):
        await bot.process_commands(message)
        return

    if message.channel.id in ACTIVE_SESSIONS:
        session = ACTIVE_SESSIONS[message.channel.id]
        try:
            os.write(session["fd"], (message.content + "\n").encode())
            log("INPUT", f"STDIN -> PID {session['proc'].pid}", CYAN)
        except OSError:
            log("ERR", f"Write failed for PID {session['proc'].pid}", RED)
            try:
                await message.channel.send("```ini\n[ SESSION DIED ]\n```")
            except Exception:
                pass
            close_session_internal(message.channel.id)

# -----------------------------------------------------
# COMMANDS
# -----------------------------------------------------

@bot.command(name="sync")
async def sync_menu(ctx):
    if not check_access(ctx): return
    await respond(ctx, "```ini\n[ SYNCING... ]\n```")
    try:
        guild = discord.Object(id=CONFIG["GUILD_ID"])
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        await respond(ctx, "```ini\n[ DONE ]\n```")
    except Exception as e:
        await respond(ctx, f"Error: {e}")

@bot.hybrid_command(name="ping", description="Ping Check")
async def ping(ctx):
    if not check_access(ctx): return
    await respond(ctx, f"```ini\n[ ONLINE: {round(bot.latency*1000)}ms ]\n```")

@bot.hybrid_command(name="sys", description="System Info")
async def sys_info(ctx):
    if not check_access(ctx): return
    try:
        u = os.popen("whoami").read().strip()
        k = os.popen("uname -sr").read().strip()
        await respond(ctx, f"```ini\n[ USER: {u} ]\n[ KERNEL: {k} ]\n```")
    except Exception:
        await respond(ctx, "Error")

@bot.hybrid_command(name="shell", description="Spawn Interactive PTY Shell")
async def spawn_shell(ctx, tool: str = "/bin/bash"):
    if not check_access(ctx): return
    if not ctx.guild: return await respond(ctx, "Servers only.")
    # don't defer here; operation is quick
    log("CMD", f"Spawning SHELL: {tool}", YELLOW)
    cname = f"pty-{random.randint(1000,9999)}-{tool.split('/')[-1]}"
    try:
        cat = ctx.guild.get_channel(CONFIG["CATEGORY_ID"]) if CONFIG["CATEGORY_ID"] else None
        new_ch = await ctx.guild.create_text_channel(cname, category=cat)

        m_fd, s_fd = pty.openpty()
        attr = termios.tcgetattr(s_fd)
        attr[3] = attr[3] & ~termios.ECHO
        termios.tcsetattr(s_fd, termios.TCSANOW, attr)

        env = os.environ.copy()
        env["TERM"] = "xterm"

        proc = subprocess.Popen(tool, shell=True, stdin=s_fd, stdout=s_fd, stderr=s_fd, preexec_fn=os.setsid, close_fds=True, env=env)

        ACTIVE_SESSIONS[new_ch.id] = {"fd": m_fd, "proc": proc}
        SESSION_BUFFERS[new_ch.id] = bytearray()
        asyncio.get_running_loop().add_reader(m_fd, read_from_pty, m_fd, new_ch.id)

        log("SHELL", f"Started PID {proc.pid} in #{new_ch.name}", GREEN)
        await respond(ctx, f"✅ **Session:** {new_ch.mention}")
        await new_ch.send(f"```ini\n[ PTY SHELL: {tool} ]\n[ PID: {proc.pid} ]\n```")
    except Exception as e:
        log("ERR", f"Spawn failed: {e}", RED)
        await respond(ctx, f"Error: {e}")

@bot.hybrid_command(name="list", description="List Active Sessions")
async def list_sessions(ctx):
    if not check_access(ctx): return
    if not ACTIVE_SESSIONS: return await respond(ctx, "```ini\n[ NO ACTIVE SESSIONS ]\n```")
    report = "\n".join([f"[ CHANNEL: {k} ] [ PID: {v['proc'].pid} ]" for k, v in ACTIVE_SESSIONS.items()])
    await respond(ctx, f"```ini\n{report}\n```")

@bot.hybrid_command(name="close", description="Close Session")
async def close_session(ctx):
    if not check_access(ctx): return
    if not await confirm_action(ctx, "CLOSE SESSION"): return
    cid = ctx.channel.id
    if cid in ACTIVE_SESSIONS:
        close_session_internal(cid)
    try:
        await ctx.channel.delete()
    except Exception:
        pass

@bot.hybrid_command(name="clear", description="Wipe Chat")
async def clear_chat(ctx, limit: int = None):
    if not check_access(ctx): return
    if isinstance(ctx.channel, discord.DMChannel): return await respond(ctx, "No DMs.")
    if not await confirm_action(ctx, "WIPE CHAT"): return
    try:
        await ctx.channel.purge(limit=limit)
        await respond(ctx, "```ini\n[ MEMORY FORMATTED ]\n```")
    except Exception:
        await respond(ctx, "Purge Failed.")

@bot.hybrid_command(name="shutdown", description="Terminate Bot")
async def shutdown(ctx):
    if not check_access(ctx): return
    if not await confirm_action(ctx, "SHUTDOWN"): return
    log("CMD", "GLOBAL SHUTDOWN", RED)
    await respond(ctx, "```css\n[ OFFLINE ]\n```")
    for cid in list(ACTIVE_SESSIONS.keys()):
        close_session_internal(cid)
    await bot.close()
    sys.exit()

# helper to escape single quotes for embedding in single-quoted shell literal
def _escape_single_quotes(s: str) -> str:
    if s is None:
        return ""
    return s.replace("'", "'\"'\"'")

@bot.hybrid_command(name="x", description="Quick Exec")
async def quick_exec(ctx, cmd: str):
    global CURRENT_SIMPLE_PROCESS
    if not check_access(ctx): return

    # Defer if this is an interaction to avoid "this is taking a while" without response.
    # Defer only when available; message-context callers won't be affected.
    try:
        if getattr(ctx, "interaction", None) is not None and not getattr(ctx.interaction.response, "is_done", False):
            await ctx.defer()
    except Exception:
        # ignore defer errors and continue
        pass

    # Log redacted command
    log("EXEC", f"Running: {_redact(cmd)}", CYAN)

    if CURRENT_SIMPLE_PROCESS:
        await respond(ctx, "⚠️ Busy. Use `/nuke`.")
        return

    try:
        CURRENT_SIMPLE_PROCESS = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(CURRENT_SIMPLE_PROCESS.communicate(), timeout=30.0)
            res = strip_ansi((out + err).decode('utf-8', errors='ignore')) or "[NULL]"
            res = _redact(res)
            log("EXEC", f"Finished: {_redact(cmd)}", GREEN)
            CURRENT_SIMPLE_PROCESS = None

            # deliver result: if short use code block, if long send file
            if len(res) < 1900:
                await respond(ctx, f"```bash\n{res}\n```")
            else:
                bio = io.BytesIO(res.encode())
                bio.seek(0)
                file = discord.File(bio, filename="out.txt")
                await respond(ctx, "Output too long, sending file:", file=file)
        except asyncio.TimeoutError:
            log("EXEC", "Timeout", RED)
            try:
                CURRENT_SIMPLE_PROCESS.kill()
            except Exception:
                pass
            CURRENT_SIMPLE_PROCESS = None
            await respond(ctx, "⏱️ Timeout.")
    except Exception as e:
        CURRENT_SIMPLE_PROCESS = None
        log("ERR", f"Exec failed: {e}", RED)
        await respond(ctx, f"Error: {e}")

@bot.hybrid_command(name="nuke", description="Kill Stuck Process")
async def nuke_process(ctx):
    global CURRENT_SIMPLE_PROCESS
    if not check_access(ctx): return
    if not CURRENT_SIMPLE_PROCESS:
        return await respond(ctx, "Nothing.")
    if not await confirm_action(ctx, "KILL"): return
    try:
        CURRENT_SIMPLE_PROCESS.kill()
        CURRENT_SIMPLE_PROCESS = None
        await respond(ctx, "Terminated.")
    except Exception:
        await respond(ctx, "Fail.")

@bot.hybrid_command(name="auth", description="Set Sudo Pass")
async def auth(ctx, password: str):
    if not check_access(ctx): return
    global SUDO_PASSWORD
    SUDO_PASSWORD = password
    log("AUTH", "Sudo password cached", MAGENTA)
    await respond(ctx, "```ini\n[ AUTH CACHED ]\n```")

@bot.hybrid_command(name="sudo", description="Sudo Exec")
async def sudo(ctx, cmd: str):
    if not check_access(ctx): return
    if not SUDO_PASSWORD:
        return await respond(ctx, "Auth first.")
    log("SUDO", f"Exec: {cmd} (Password hidden)", RED)
    esc = _escape_single_quotes(SUDO_PASSWORD)
    shell_cmd = f"printf '%s\\n' '{esc}' | sudo -S -n -p '' {cmd}"
    # ensure quick_exec handles defers and follows up
    await quick_exec.callback(ctx, shell_cmd)

if __name__ == "__main__":
    if CONFIG["TOKEN"].startswith("ВСТАВ"):
        print(f"{RED}[CRITICAL] CONFIG ERROR.{RESET}")
        sys.exit()
    try:
        bot.run(CONFIG["TOKEN"])
    except Exception as e:
        print(f"{RED}[FATAL] {e}{RESET}")
