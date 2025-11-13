import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ChevronDown, Shield, Cpu, Lock } from "lucide-react";
import { useState } from "react";

export function TechnicalSpecs() {
  const [openItems, setOpenItems] = useState<string[]>(["cpu", "quantum", "anti"]);

  const toggleItem = (item: string) => {
    setOpenItems(prev =>
      prev.includes(item) ? prev.filter(i => i !== item) : [...prev, item]
    );
  };

  return (
    <section className="py-16 lg:py-24 bg-muted/30">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Đặc Điểm <span className="text-primary">Kỹ Thuật</span>
        </h2>

        <Card className="border-primary/30 shadow-lg shadow-primary/5 overflow-hidden" data-testid="card-technical-specs">
          <CardHeader className="bg-gradient-to-r from-primary/5 to-transparent border-b border-primary/20">
            <CardTitle className="font-display text-2xl flex items-center gap-2">
              <span className="text-primary font-mono">$</span> Cơ Chế Bảo Vệ
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              <Collapsible open={openItems.includes("cpu")} onOpenChange={() => toggleItem("cpu")}>
                <CollapsibleTrigger 
                  className="w-full px-6 py-4 flex items-center justify-between hover-elevate transition-all"
                  data-testid="trigger-cpu-detection"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-primary/10">
                      <Cpu className="w-5 h-5 text-primary" />
                    </div>
                    <div className="text-left">
                      <div className="font-semibold font-mono">CPUID Checking</div>
                      <div className="text-xs text-muted-foreground">Kiểm tra vendor string và CPU features</div>
                    </div>
                  </div>
                  <ChevronDown className={`w-5 h-5 transition-transform ${openItems.includes("cpu") ? "rotate-180" : ""}`} />
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="px-6 py-4 bg-card/50 border-t border-primary/10">
                    <p className="text-sm text-muted-foreground mb-3" style={{ lineHeight: "1.7" }}>
                      Chương trình sử dụng instruction CPUID để nhận dạng phần cứng và xác định loại CPU. 
                      Kiểm tra vendor string (Intel/AMD) và các CPU features đặc biệt.
                    </p>
                    <div className="bg-background rounded-md p-4 font-mono text-xs border border-border">
                      <div className="text-muted-foreground mb-2">// CPUID detection example</div>
                      <div><span className="text-chart-4">cpuid</span> <span className="text-muted-foreground">// Execute CPUID instruction</span></div>
                      <div><span className="text-chart-4">cmp</span> eax, <span className="text-primary">"Quant"</span></div>
                      <div><span className="text-chart-4">jne</span> fail_exit</div>
                    </div>
                  </div>
                </CollapsibleContent>
              </Collapsible>

              <Collapsible open={openItems.includes("quantum")} onOpenChange={() => toggleItem("quantum")}>
                <CollapsibleTrigger 
                  className="w-full px-6 py-4 flex items-center justify-between hover-elevate transition-all"
                  data-testid="trigger-quantum-requirement"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-chart-2/10">
                      <Shield className="w-5 h-5 text-chart-2" />
                    </div>
                    <div className="text-left">
                      <div className="font-semibold font-mono">Quantum CPU Emulation</div>
                      <div className="text-xs text-muted-foreground">Yêu cầu CPU type đặc biệt trong QEMU</div>
                    </div>
                  </div>
                  <ChevronDown className={`w-5 h-5 transition-transform ${openItems.includes("quantum") ? "rotate-180" : ""}`} />
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="px-6 py-4 bg-card/50 border-t border-chart-2/10">
                    <p className="text-sm text-muted-foreground mb-3" style={{ lineHeight: "1.7" }}>
                      Binary chỉ hoạt động khi được chạy trong môi trường QEMU với CPU type "quantum". 
                      Đây là một CPU model tùy chỉnh không tồn tại trong QEMU mặc định.
                    </p>
                    <div className="bg-background rounded-md p-4 font-mono text-xs border border-border">
                      <div className="text-muted-foreground mb-2"># QEMU command</div>
                      <div><span className="text-primary">qemu-system-x86_64</span> <span className="text-chart-4">-cpu</span> quantum binary.elf</div>
                    </div>
                  </div>
                </CollapsibleContent>
              </Collapsible>

              <Collapsible open={openItems.includes("anti")} onOpenChange={() => toggleItem("anti")}>
                <CollapsibleTrigger 
                  className="w-full px-6 py-4 flex items-center justify-between hover-elevate transition-all"
                  data-testid="trigger-anti-analysis"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-destructive/10">
                      <Lock className="w-5 h-5 text-destructive" />
                    </div>
                    <div className="text-left">
                      <div className="font-semibold font-mono">Anti-analysis</div>
                      <div className="text-xs text-muted-foreground">Chống dịch ngược và debug</div>
                    </div>
                  </div>
                  <ChevronDown className={`w-5 h-5 transition-transform ${openItems.includes("anti") ? "rotate-180" : ""}`} />
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="px-6 py-4 bg-card/50 border-t border-destructive/10">
                    <p className="text-sm text-muted-foreground mb-3" style={{ lineHeight: "1.7" }}>
                      Binary triển khai nhiều kỹ thuật anti-debugging và anti-analysis để ngăn chặn việc phân tích tĩnh và động.
                    </p>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-start gap-2">
                        <span className="text-destructive mt-1">▸</span>
                        <span>Hardware-specific code execution</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-destructive mt-1">▸</span>
                        <span>QEMU environment detection</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-destructive mt-1">▸</span>
                        <span>Code obfuscation và packing</span>
                      </li>
                    </ul>
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
