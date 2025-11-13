import { useState } from "react";
import { Code, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const CODE_EXAMPLES = {
  vulnerable: `#include <iostream>
#include <cstring>
#include <climits>

// The Undefined - CTF Pwn Challenge
// WARNING: Contains intentional undefined behavior

class FlagEncryptor {
private:
    int secret_key;  // [UB] Uninitialized variable
    
public:
    void encrypt_flag(char* flag, size_t len) {
        // [UB] Reading uninitialized memory
        for (size_t i = 0; i < len; i++) {
            flag[i] ^= (secret_key >> (i % 32)) & 0xFF;
        }
    }
    
    uint32_t derive_key_from_ub() {
        uint32_t a = 0x12345678;
        
        // [UB] Type punning / Strict aliasing violation
        float* b = (float*)&a;
        float val = *b;
        
        // [UB] Signed integer overflow
        int x = INT_MAX;
        x += (int)val;  
        
        return (uint32_t)x ^ secret_key;
    }
};

int main() {
    char flag[] = "VNFLAG{...censored...}";
    FlagEncryptor enc;
    
    enc.encrypt_flag(flag, strlen(flag));
    
    std::cout << "Encrypted: ";
    for (size_t i = 0; i < strlen(flag); i++) {
        printf("%02x", (unsigned char)flag[i]);
    }
    std::cout << std::endl;
    
    return 0;
}`,
  
  assembly: `; Disassembly of encrypt_flag function
encrypt_flag:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    mov     QWORD PTR [rbp-8], rdi
    mov     QWORD PTR [rbp-16], rsi
    mov     DWORD PTR [rbp-20], 0
.L3:
    mov     eax, DWORD PTR [rbp-20]
    cdqe
    cmp     rax, QWORD PTR [rbp-16]
    jnb     .L4
    ; Critical: Loading uninitialized value
    mov     eax, DWORD PTR [rbp-4]   ; [UB] HERE!
    mov     ecx, eax
    mov     eax, DWORD PTR [rbp-20]
    cdq
    mov     edx, eax
    shr     edx, 27
    add     eax, edx
    and     eax, 31
    sub     eax, edx
    mov     edx, eax
    sar     ecx, cl
    mov     eax, ecx
    and     eax, 255
    ; Continue encryption...`,

  gdb: `(gdb) break encrypt_flag
Breakpoint 1 at 0x5555555551a0

(gdb) run
Starting program: ./the_undefined 

Breakpoint 1, encrypt_flag() at the_undefined.cpp:12

(gdb) info registers
rax            0x7fffffffdc60      140737488346208
rbp            0x7fffffffdc50      0x7fffffffdc50
rsp            0x7fffffffdc40      0x7fffffffdc40

(gdb) x/16x $rsp
0x7fffffffdc40: 0xf7e1d083  0x00007fff  0x00000001  0x00000000
0x7fffffffdc50: 0xffffdc70  0x00007fff  0x555551e9  0x00005555
0x7fffffffdc60: 0x464e5600  0x7b47414c  0xdeadbeef  0xcafebabe
                                         ^^^^^^^^  [UB] Uninitialized!

(gdb) print secret_key
$1 = -559038737  ; Random garbage from stack!`,
};

export function CodeViewer() {
  const [activeTab, setActiveTab] = useState("vulnerable");
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(CODE_EXAMPLES[activeTab as keyof typeof CODE_EXAMPLES]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div 
      className="rounded-md overflow-hidden"
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(34, 211, 238, 0.2)',
      }}
    >
      <div 
        className="px-4 py-2 border-b flex items-center justify-between"
        style={{
          backgroundColor: 'rgba(34, 211, 238, 0.05)',
          borderColor: 'rgba(34, 211, 238, 0.2)',
        }}
      >
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-terminal-cyan" />
          <span className="text-sm font-semibold text-terminal-cyan">Source Code Analysis</span>
        </div>
        
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              size="sm"
              variant="ghost"
              onClick={handleCopy}
              className="h-7 px-2 text-terminal-text-muted hover:text-terminal-cyan"
              data-testid="button-copy-code"
            >
              {copied ? (
                <Check className="w-4 h-4" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <p>{copied ? "Copied!" : "Copy code"}</p>
          </TooltipContent>
        </Tooltip>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList 
          className="w-full justify-start rounded-none h-10 p-0 border-b"
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
            borderColor: 'rgba(34, 211, 238, 0.2)',
          }}
        >
          <TabsTrigger 
            value="vulnerable"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan"
            data-testid="tab-vulnerable-code"
          >
            Vulnerable Code
          </TabsTrigger>
          <TabsTrigger 
            value="assembly"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan"
            data-testid="tab-assembly"
          >
            Assembly
          </TabsTrigger>
          <TabsTrigger 
            value="gdb"
            className="data-[state=active]:bg-terminal-surface data-[state=active]:text-terminal-cyan text-terminal-text-muted rounded-none border-b-2 border-transparent data-[state=active]:border-terminal-cyan"
            data-testid="tab-gdb-output"
          >
            GDB Output
          </TabsTrigger>
        </TabsList>

        {Object.entries(CODE_EXAMPLES).map(([key, code]) => (
          <TabsContent key={key} value={key} className="mt-0">
            <div className="relative">
              <pre 
                className="p-4 overflow-x-auto font-mono text-sm leading-relaxed"
                style={{
                  backgroundColor: '#0a0e14',
                  color: '#e5e7eb',
                  maxHeight: '500px',
                  overflowY: 'auto',
                }}
                data-testid={`code-content-${key}`}
              >
                <code>{code}</code>
              </pre>
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
