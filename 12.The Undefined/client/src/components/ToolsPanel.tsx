import { Wrench, Database, Binary } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const GDB_OUTPUT = `(gdb) info proc mappings
process 1337
Mapped address spaces:

    Start Addr           End Addr       Size     Offset  Perms  objfile
0x555555554000   0x555555555000     0x1000        0x0  r--p   /home/ctf/the_undefined
0x555555555000   0x555555556000     0x1000     0x1000  r-xp   /home/ctf/the_undefined
0x555555556000   0x555555557000     0x1000     0x2000  r--p   /home/ctf/the_undefined
0x7ffff7dd5000   0x7ffff7dfa000    0x25000        0x0  r--p   /lib/x86_64-linux-gnu/libc.so.6
0x7ffff7dfa000   0x7ffff7f8f000   0x195000    0x25000  r-xp   /lib/x86_64-linux-gnu/libc.so.6
0x7ffffffde000   0x7ffffffff000    0x21000        0x0  rw-p   [stack]

(gdb) x/32x 0x7ffffffde000
0x7ffffffde000: 0x00000000  0x00000000  0xf7e2d565  0x00007fff
0x7ffffffde010: 0x00000001  0x00000000  0xffffdf48  0x00007fff
0x7ffffffde020: 0xdeadbeef  0xcafebabe  0x13371337  0xbaadf00d
                ^^^^^^^^^^  ^^^^^^^^^^  [UB] Uninitialized stack data!`;

const MEMORY_DUMP = `Memory dump at encryption key location:

Address          Hex Values                       ASCII
----------------------------------------------------------------
0x7ffd4c2df8e0:  de ad be ef ca fe ba be  13 37 13 37  ........ .7.7
0x7ffd4c2df8f0:  ba ad f0 0d 00 00 00 00  56 4e 46 4c  ........ VNFL
0x7ffd4c2df900:  41 47 7b 54 41 4d 5f 48  55 59 45 54  AG{TAM_H UYET
0x7ffd4c2df910:  5f 59 45 55 5f 4e 55 4f  43 5f 56 49  _YEU_NUO C_VI

Stack Layout Analysis:
- Uninitialized variable at offset -0x8 from RBP
- Contains garbage values from previous function calls
- Key depends on: compiler version, optimization level, ASLR state
- Reproducibility requires: fixed environment, disabled ASLR`;

const BINARY_ANALYSIS = `Binary Security Analysis:
═══════════════════════════════════════════════════════════

File: the_undefined (ELF 64-bit LSB executable)
Arch: x86-64

Security Protections:
┌─────────────────┬──────────┬─────────────────────────────┐
│ Protection      │ Status   │ Impact                      │
├─────────────────┼──────────┼─────────────────────────────┤
│ RELRO           │ Partial  │ GOT partially protected     │
│ Stack Canary    │ Enabled  │ Stack overflow mitigation   │
│ NX              │ Enabled  │ No executable stack         │
│ PIE             │ Enabled  │ Address randomization       │
│ ASLR            │ Enabled  │ Memory layout randomized    │
└─────────────────┴──────────┴─────────────────────────────┘

Undefined Behavior Detected:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Uninitialized Memory Read
   Location: encrypt_flag() at offset 0x1158
   Severity: HIGH
   
2. Type Punning / Strict Aliasing Violation
   Location: derive_key_from_ub() at offset 0x11a3
   Severity: MEDIUM
   
3. Signed Integer Overflow
   Location: derive_key_from_ub() at offset 0x11b2
   Severity: MEDIUM

Exploitation Strategy:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
→ Control compilation environment to fix UB behavior
→ Disable ASLR to make memory layout predictable
→ Use GDB to extract encryption key at runtime
→ XOR-decrypt flag with extracted key`;

export function ToolsPanel() {
  return (
    <div 
      className="rounded-md overflow-hidden"
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(34, 211, 238, 0.2)',
      }}
    >
      <div 
        className="px-4 py-2 border-b flex items-center gap-2"
        style={{
          backgroundColor: 'rgba(34, 211, 238, 0.05)',
          borderColor: 'rgba(34, 211, 238, 0.2)',
        }}
        data-testid="header-tools-panel"
      >
        <Wrench className="w-4 h-4 text-terminal-cyan" />
        <span className="text-sm font-semibold text-terminal-cyan">Analysis Tools</span>
      </div>

      <Tabs defaultValue="gdb" className="w-full">
        <TabsList 
          className="w-full justify-start rounded-none h-10 p-0 border-b"
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
            borderColor: 'rgba(34, 211, 238, 0.2)',
          }}
        >
          <TabsTrigger 
            value="gdb"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan gap-2"
            data-testid="tab-gdb-analysis"
          >
            <Binary className="w-3.5 h-3.5" />
            GDB Analysis
          </TabsTrigger>
          <TabsTrigger 
            value="memory"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan gap-2"
            data-testid="tab-memory-dump"
          >
            <Database className="w-3.5 h-3.5" />
            Memory Dump
          </TabsTrigger>
          <TabsTrigger 
            value="binary"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan gap-2"
            data-testid="tab-binary-info"
          >
            <Wrench className="w-3.5 h-3.5" />
            Binary Info
          </TabsTrigger>
        </TabsList>

        <TabsContent value="gdb" className="mt-0">
          <pre 
            className="p-4 font-mono text-sm leading-relaxed overflow-x-auto"
            style={{
              backgroundColor: '#0a0e14',
              color: '#4ade80',
              maxHeight: '400px',
              overflowY: 'auto',
            }}
            data-testid="content-gdb-analysis"
          >
            {GDB_OUTPUT}
          </pre>
        </TabsContent>

        <TabsContent value="memory" className="mt-0">
          <pre 
            className="p-4 font-mono text-sm leading-relaxed overflow-x-auto"
            style={{
              backgroundColor: '#0a0e14',
              color: '#4ade80',
              maxHeight: '400px',
              overflowY: 'auto',
            }}
            data-testid="content-memory-dump"
          >
            {MEMORY_DUMP}
          </pre>
        </TabsContent>

        <TabsContent value="binary" className="mt-0">
          <pre 
            className="p-4 font-mono text-sm leading-relaxed overflow-x-auto"
            style={{
              backgroundColor: '#0a0e14',
              color: '#4ade80',
              maxHeight: '400px',
              overflowY: 'auto',
            }}
            data-testid="content-binary-info"
          >
            {BINARY_ANALYSIS}
          </pre>
        </TabsContent>
      </Tabs>
    </div>
  );
}
