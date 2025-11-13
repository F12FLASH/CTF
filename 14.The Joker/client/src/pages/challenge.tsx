import { useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CodeBlock } from "@/components/code-block";
import { FlagSubmissionForm } from "@/components/flag-submission";
import { ProgressTracker } from "@/components/progress-tracker";
import { BinaryDownload } from "@/components/binary-download";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { apiRequest } from "@/lib/queryClient";
import { type InsertProgress } from "@shared/schema";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Terminal, 
  Code2, 
  Database, 
  Lock, 
  Zap, 
  Bug, 
  Shield, 
  Cpu, 
  FileSearch,
  Wrench,
  Book
} from "lucide-react";

export default function ChallengePage() {
  const [activeSection, setActiveSection] = useState<string>("");
  const [markedSections, setMarkedSections] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  const markSectionMutation = useMutation({
    mutationFn: async (data: InsertProgress) => {
      return await apiRequest("POST", "/api/mark-section", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/progress"] });
    },
  });

  useEffect(() => {
    const handleScroll = () => {
      const sections = document.querySelectorAll("[data-section]");
      let current = "";

      sections.forEach((section) => {
        const sectionTop = section.getBoundingClientRect().top;
        if (sectionTop <= 100) {
          current = section.getAttribute("data-section") || "";
        }
      });

      if (current) {
        setActiveSection(current);
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && entry.intersectionRatio > 0.5) {
            const sectionId = entry.target.getAttribute("data-section");
            if (sectionId && !markedSections.has(sectionId)) {
              setMarkedSections((prev) => new Set(prev).add(sectionId));
              markSectionMutation.mutate({
                sectionId,
                completed: true,
              });
            }
          }
        });
      },
      {
        threshold: 0.5,
        rootMargin: "-100px 0px -100px 0px",
      }
    );

    const sections = document.querySelectorAll("[data-section]");
    sections.forEach((section) => observer.observe(section));

    return () => {
      sections.forEach((section) => observer.unobserve(section));
    };
  }, [markSectionMutation, markedSections]);

  const scrollToSection = (sectionId: string) => {
    const element = document.querySelector(`[data-section="${sectionId}"]`);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const navigationItems = [
    { id: "overview", label: "Tổng quan", icon: Book },
    { id: "protection", label: "Cơ chế bảo vệ", icon: Shield },
    { id: "static-analysis", label: "Phân tích tĩnh", icon: FileSearch },
    { id: "gdb-scripting", label: "GDB Scripting", icon: Terminal },
    { id: "memory-tracing", label: "Memory Tracing", icon: Database },
    { id: "ld-preload", label: "LD_PRELOAD", icon: Code2 },
    { id: "binary-patching", label: "Binary Patching", icon: Wrench },
  ];

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden lg:block w-64 border-r border-border bg-card/30 sticky top-0 h-screen">
        <ScrollArea className="h-full">
          <div className="p-6 space-y-6">
            <div>
              <h2 className="text-lg font-semibold mb-4">Nội dung</h2>
              <nav className="space-y-1">
                {navigationItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeSection === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => scrollToSection(item.id)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-2 hover-elevate ${
                        isActive ? 'bg-primary/10 text-primary' : 'text-muted-foreground'
                      }`}
                      data-testid={`nav-${item.id}`}
                    >
                      <Icon className="h-4 w-4 flex-shrink-0" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </nav>
            </div>
            <Separator />
            <div className="space-y-3">
              <ProgressTracker />
            </div>
          </div>
        </ScrollArea>
      </aside>

      <main className="flex-1">
        <div className="relative overflow-hidden bg-gradient-to-b from-primary/5 to-background border-b border-border">
          <div className="absolute inset-0 bg-grid-white/[0.02] bg-[size:50px_50px]" />
          <div className="relative max-w-4xl mx-auto px-6 py-16 space-y-6">
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary" className="gap-1.5">
                <Terminal className="h-3 w-3" />
                Reverse Engineering
              </Badge>
              <Badge variant="secondary" className="gap-1.5">
                <Lock className="h-3 w-3" />
                Anti-debugging
              </Badge>
              <Badge variant="secondary" className="gap-1.5">
                <Bug className="h-3 w-3" />
                Ptrace
              </Badge>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
              The Joker
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl">
              Binary tinh vi sử dụng kỹ thuật anti-debugging và self-modification để xóa chính nó khỏi bộ nhớ. 
              Một thử thách về cuộc chạy đua giữa reverse engineering và các cơ chế phòng thủ.
            </p>
            <div className="flex items-center gap-6 pt-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Độ khó:</span>
                <Badge variant="outline" className="font-mono">Expert (4/4)</Badge>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-4xl mx-auto px-6 py-12 space-y-12">
          
            <section data-section="overview" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Book className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Tổng quan</CardTitle>
                    <CardDescription>Giới thiệu về thử thách "The Joker"</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm leading-relaxed text-muted-foreground">
                  <strong className="text-foreground">"The Joker"</strong> là một binary tinh vi có hành vi như một "trò đùa" - 
                  nó hiển thị flag cho người dùng nhưng ngay lập tức sử dụng kỹ thuật anti-debugging và self-modification 
                  để xóa chính nó khỏi bộ nhớ, khiến người dùng không kịp ghi lại flag.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                  <div className="p-4 rounded-lg bg-muted/50 border border-border space-y-2">
                    <div className="flex items-center gap-2">
                      <Cpu className="h-4 w-4 text-primary" />
                      <span className="text-sm font-semibold">Đặc điểm kỹ thuật</span>
                    </div>
                    <ul className="text-sm space-y-1 text-muted-foreground pl-6">
                      <li className="list-disc">In flag ra màn hình</li>
                      <li className="list-disc">Sử dụng ptrace(PTRACE_TRACEME)</li>
                      <li className="list-disc">Tự xóa code và data khỏi memory</li>
                      <li className="list-disc">Xóa memory ngay sau khi in flag</li>
                    </ul>
                  </div>

                  <div className="p-4 rounded-lg bg-muted/50 border border-border space-y-2">
                    <div className="flex items-center gap-2">
                      <Zap className="h-4 w-4 text-primary" />
                      <span className="text-sm font-semibold">Kỹ năng yêu cầu</span>
                    </div>
                    <ul className="text-sm space-y-1 text-muted-foreground pl-6">
                      <li className="list-disc">Thành thạo GDB</li>
                      <li className="list-disc">Process memory layout</li>
                      <li className="list-disc">Anti-debugging bypass</li>
                      <li className="list-disc">Binary analysis</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="protection" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Shield className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Cơ chế bảo vệ</CardTitle>
                    <CardDescription>Các kỹ thuật được sử dụng trong binary</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <Accordion type="single" collapsible className="w-full">
                  <AccordionItem value="ptrace">
                    <AccordionTrigger className="text-sm font-semibold">
                      <div className="flex items-center gap-2">
                        <Lock className="h-4 w-4 text-primary" />
                        Ptrace Anti-debug
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="space-y-3">
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        Binary sử dụng ptrace(PTRACE_TRACEME) để phát hiện debugger. Nếu phát hiện, nó sẽ xóa memory ngay lập tức.
                      </p>
                      <CodeBlock
                        language="c"
                        filename="anti-debug.c"
                        code={`if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // Phát hiện debugger - xóa memory ngay lập tức
    erase_memory();
    exit(0);
}`}
                      />
                    </AccordionContent>
                  </AccordionItem>

                  <AccordionItem value="memory-wiping">
                    <AccordionTrigger className="text-sm font-semibold">
                      <div className="flex items-center gap-2">
                        <Database className="h-4 w-4 text-primary" />
                        Memory Wiping
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="space-y-3">
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        Binary ghi đè memory chứa flag và code với zeros, sau đó flush cache.
                      </p>
                      <CodeBlock
                        language="c"
                        filename="memory-wipe.c"
                        code={`void erase_memory() {
    char *flag_addr = get_flag_address();
    char *code_addr = get_code_address();
    
    // Ghi đè memory với zeros
    memset(flag_addr, 0, FLAG_LENGTH);
    memset(code_addr, 0, CODE_SIZE);
    
    // Flush cache
    __builtin___clear_cache(code_addr, code_addr + CODE_SIZE);
}`}
                      />
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="static-analysis" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <FileSearch className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Bước 1: Phân tích tĩnh</CardTitle>
                    <CardDescription>Kiểm tra binary và cấu trúc</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Bước đầu tiên là phân tích binary mà không chạy nó để hiểu cấu trúc và các protection mechanisms.
                </p>
                <CodeBlock
                  language="bash"
                  filename="static-analysis.sh"
                  code={`# Kiểm tra binary
file the_joker
checksec --file=the_joker
strings the_joker | grep -i flag

# Disassembly
objdump -d the_joker | less`}
                />
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="gdb-scripting" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Terminal className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Phương pháp 1: GDB Scripting</CardTitle>
                    <CardDescription>Dump memory trước khi bị xóa (Độ khó: 4/4)</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Sử dụng GDB script tự động để đặt breakpoint tại hàm in flag và dump memory trước khi bị xóa.
                </p>
                <CodeBlock
                  language="gdb"
                  filename="debug_joker.gdb"
                  showLineNumbers
                  code={`set pagination off
set follow-fork-mode child

# Breakpoint tại hàm in flag
break print_flag
commands
  # Dump memory trước khi bị xóa
  dump binary memory flag_dump.bin $rsi $rsi+100
  continue
end

# Bypass ptrace check
catch syscall ptrace
commands
  set $rax = 0  # Return success
  continue
end

run`}
                />
                <div className="pt-2">
                  <p className="text-sm font-semibold mb-2">Chạy script:</p>
                  <CodeBlock
                    language="bash"
                    code={`gdb -x debug_joker.gdb ./the_joker`}
                  />
                </div>
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="memory-tracing" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Database className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Phương pháp 2: Memory Tracing</CardTitle>
                    <CardDescription>Sử dụng ptrace để trace process (Độ khó: 4/4)</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Viết custom tracer program sử dụng ptrace để monitor và dump memory của process.
                </p>
                <CodeBlock
                  language="c"
                  filename="tracer.c"
                  showLineNumbers
                  code={`#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./the_joker", "./the_joker", NULL);
    } else {
        int status;
        while (waitpid(child, &status, 0)) {
            if (WIFSTOPPED(status)) {
                // Dump memory tại mỗi stop
                dump_memory(child);
                ptrace(PTRACE_CONT, child, NULL, NULL);
            }
        }
    }
    return 0;
}`}
                />
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="ld-preload" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Code2 className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Phương pháp 3: LD_PRELOAD Hook</CardTitle>
                    <CardDescription>Hook ptrace function (Độ khó: 3/4)</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Sử dụng LD_PRELOAD để hook ptrace function và bypass anti-debugging check.
                </p>
                <CodeBlock
                  language="c"
                  filename="hook_ptrace.c"
                  showLineNumbers
                  code={`#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long ptrace(enum __ptrace_request request, pid_t pid, 
            void *addr, void *data) {
    static long (*real_ptrace)(enum __ptrace_request, pid_t, void*, void*);
    real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    
    if (request == PTRACE_TRACEME) {
        return 0; // Bypass anti-debug
    }
    return real_ptrace(request, pid, addr, data);
}`}
                />
                <div className="space-y-2 pt-2">
                  <p className="text-sm font-semibold">Compile và sử dụng:</p>
                  <CodeBlock
                    language="bash"
                    code={`gcc -shared -fPIC -o hook_ptrace.so hook_ptrace.c -ldl
LD_PRELOAD=./hook_ptrace.so gdb ./the_joker`}
                  />
                </div>
              </CardContent>
            </Card>
          </section>
          

          
            <section data-section="binary-patching" className="scroll-mt-24">
              <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
                    <Wrench className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-2xl">Phương pháp 4: Binary Patching</CardTitle>
                    <CardDescription>Patch ptrace call thành NOP</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Sửa đổi binary trực tiếp để disable ptrace check bằng cách thay thế call instruction với NOP.
                </p>
                <CodeBlock
                  language="bash"
                  filename="patch.sh"
                  code={`# Patch ptrace call thành NOP
objcopy --dump-section .text=text_section ./the_joker
# Sửa text_section (thay ptrace call bằng NOPs)
objcopy --update-section .text=text_section ./the_joker_patched`}
                />
              </CardContent>
            </Card>
          </section>
          

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <BinaryDownload />
            <FlagSubmissionForm />
          </div>
        </div>
      </main>
    </div>
  );
}
