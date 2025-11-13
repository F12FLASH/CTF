import { useState, useRef, useEffect } from "react";
import { Terminal as TerminalIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface TerminalLine {
  type: 'command' | 'output';
  content: string;
  timestamp: number;
}

export function TerminalEmulator() {
  const [lines, setLines] = useState<TerminalLine[]>([
    { type: 'output', content: 'Welcome to The Undefined Binary Analyzer', timestamp: Date.now() },
    { type: 'output', content: 'Type "help" for available commands', timestamp: Date.now() + 100 },
    { type: 'output', content: '', timestamp: Date.now() + 200 },
  ]);
  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  const handleCommand = (cmd: string) => {
    if (!cmd.trim()) return;

    setLines(prev => [...prev, { type: 'command', content: cmd, timestamp: Date.now() }]);

    setTimeout(() => {
      const response = getCommandResponse(cmd.trim().toLowerCase());
      setLines(prev => [...prev, { type: 'output', content: response, timestamp: Date.now() }]);
    }, 100);

    setInput('');
  };

  const getCommandResponse = (cmd: string): string => {
    if (cmd === 'help') {
      return `Available commands:
  help          - Show this help message
  file          - Display binary information
  checksec      - Check security protections
  strings       - Extract strings from binary
  objdump       - Display object file information
  gdb           - Launch GDB debugger (simulated)
  clear         - Clear terminal`;
    }

    if (cmd === 'file') {
      return `the_undefined: ELF 64-bit LSB executable, x86-64, version 1 (SYSV)
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2
BuildID[sha1]=7f2d8c3a1b9e4f6d5a8c2e1f3b4a5c6d7e8f9a0b
for GNU/Linux 3.2.0, with debug_info, not stripped`;
    }

    if (cmd === 'checksec') {
      return `RELRO:           Partial RELRO
Stack Canary:    Canary found
NX:              NX enabled
PIE:             PIE enabled
ASLR:            Enabled`;
    }

    if (cmd === 'strings') {
      return `GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0
/lib64/ld-linux-x86-64.so.2
libc.so.6
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Encrypted flag: [randomized each execution]
Encryption key derived from undefined behavior`;
    }

    if (cmd === 'objdump') {
      return `Disassembly of section .text:

0000000000001149 <encrypt_flag>:
    1149:   55                      push   %rbp
    114a:   48 89 e5                mov    %rsp,%rbp
    114d:   48 83 ec 10             sub    $0x10,%rsp
    1151:   c7 45 fc 00 00 00 00    movl   $0x0,-0x4(%rbp)
    ; Warning: Uninitialized variable usage detected
    1158:   8b 45 f8                mov    -0x8(%rbp),%eax  ; UB!`;
    }

    if (cmd === 'gdb') {
      return `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
Reading symbols from ./the_undefined...
(gdb) break encrypt_flag
Breakpoint 1 at 0x1149
(gdb) run
Starting program: /home/ctf/the_undefined

Note: Use 'x/16x $rsp' to examine stack memory`;
    }

    if (cmd === 'clear') {
      setLines([
        { type: 'output', content: 'Terminal cleared', timestamp: Date.now() },
        { type: 'output', content: '', timestamp: Date.now() + 100 },
      ]);
      return '';
    }

    return `Command not found: ${cmd}
Type "help" for available commands`;
  };

  return (
    <div 
      className="rounded-md overflow-hidden"
      style={{
        backgroundColor: '#0a0e14',
        border: '1px solid rgba(34, 211, 238, 0.3)',
        boxShadow: '0 0 10px rgba(0, 255, 159, 0.2)',
      }}
    >
      <div 
        className="px-4 py-2 border-b flex items-center gap-2"
        style={{
          backgroundColor: 'rgba(34, 211, 238, 0.05)',
          borderColor: 'rgba(34, 211, 238, 0.2)',
        }}
        data-testid="header-terminal"
      >
        <TerminalIcon className="w-4 h-4 text-terminal-cyan" />
        <span className="text-sm font-semibold text-terminal-cyan">Binary Terminal</span>
      </div>

      <div 
        ref={scrollRef}
        className="p-4 h-80 overflow-y-auto font-mono text-sm"
        style={{
          color: '#39ff14',
        }}
        data-testid="terminal-output"
      >
        {lines.map((line, idx) => (
          <div key={`${line.timestamp}-${idx}`} className="mb-1">
            {line.type === 'command' ? (
              <div className="flex gap-2">
                <span className="text-terminal-cyan">$</span>
                <span className="text-terminal-text">{line.content}</span>
              </div>
            ) : (
              <pre className="whitespace-pre-wrap text-terminal-green-dim">
                {line.content}
              </pre>
            )}
          </div>
        ))}
        <div className="flex gap-2">
          <span className="text-terminal-cyan">$</span>
          <span className="text-terminal-cyan animate-blink">_</span>
        </div>
      </div>

      <div 
        className="px-4 py-3 border-t flex gap-2"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.3)',
          borderColor: 'rgba(34, 211, 238, 0.2)',
        }}
      >
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleCommand(input);
          }}
          placeholder="Type a command..."
          className="font-mono text-sm bg-transparent border-none text-terminal-text placeholder:text-terminal-text-muted focus-visible:ring-0"
          data-testid="input-terminal-command"
        />
        <Button
          onClick={() => handleCommand(input)}
          size="sm"
          className="font-mono"
          style={{
            backgroundColor: '#00ff9f',
            color: '#0a0e14',
          }}
          data-testid="button-execute-command"
        >
          Run
        </Button>
      </div>
    </div>
  );
}
