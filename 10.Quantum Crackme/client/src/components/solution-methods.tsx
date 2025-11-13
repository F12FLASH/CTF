import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Code2, Terminal, Bug } from "lucide-react";

export function SolutionMethods() {
  return (
    <section className="py-16 lg:py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Phương Pháp <span className="text-primary">Giải Quyết</span>
        </h2>

        <Tabs defaultValue="method1" className="w-full">
          <TabsList className="grid w-full grid-cols-1 sm:grid-cols-3 h-auto gap-2 bg-transparent p-0 mb-8">
            <TabsTrigger 
              value="method1" 
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground font-mono text-sm py-3 border border-border data-[state=active]:border-primary"
              data-testid="tab-method1"
            >
              <Code2 className="w-4 h-4 mr-2" />
              Patch CPUID
            </TabsTrigger>
            <TabsTrigger 
              value="method2"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground font-mono text-sm py-3 border border-border data-[state=active]:border-primary"
              data-testid="tab-method2"
            >
              <Terminal className="w-4 h-4 mr-2" />
              Dịch Ngược QEMU
            </TabsTrigger>
            <TabsTrigger 
              value="method3"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground font-mono text-sm py-3 border border-border data-[state=active]:border-primary"
              data-testid="tab-method3"
            >
              <Bug className="w-4 h-4 mr-2" />
              Dynamic Analysis
            </TabsTrigger>
          </TabsList>

          <TabsContent value="method1" data-testid="content-method1">
            <Card className="border-primary/20" data-testid="card-method1">
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <CardTitle className="font-display text-2xl">Phương Pháp 1: Patch CPUID</CardTitle>
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map((star, idx) => (
                      <span key={idx} className="text-chart-4 text-lg">⭐</span>
                    ))}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3 text-sm uppercase tracking-wider text-muted-foreground">Các Bước Thực Hiện</h4>
                  <ol className="space-y-3">
                    {[
                      { step: "Phân tích binary", desc: "Xác định vị trí kiểm tra CPUID" },
                      { step: "Disassembly", desc: "Dịch ngược code kiểm tra CPU vendor" },
                      { step: "Binary Patching", desc: "Sửa đổi instruction CPUID hoặc kết quả so sánh" },
                      { step: "Bypass Check", desc: "Vô hiệu hóa kiểm tra quantum CPU" }
                    ].map((item, idx) => (
                      <li key={idx} className="flex gap-3" data-testid={`step-method1-${idx}`}>
                        <Badge variant="outline" className="font-mono shrink-0 h-6">{idx + 1}</Badge>
                        <div>
                          <div className="font-semibold">{item.step}</div>
                          <div className="text-sm text-muted-foreground">{item.desc}</div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <h4 className="font-semibold mb-3 text-sm uppercase tracking-wider text-muted-foreground">Kỹ Thuật Patching</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">▸</span>
                      <span><strong>Inline Patch:</strong> Thay thế instruction CPUID bằng NOP hoặc mov</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">▸</span>
                      <span><strong>Result Manipulation:</strong> Hook hàm trả về kết quả CPUID</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">▸</span>
                      <span><strong>Condition Bypass:</strong> Sửa jump conditions để luôn pass</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-background rounded-md p-4 font-mono text-xs border border-border overflow-x-auto">
                  <div className="text-muted-foreground mb-2">// Example CPUID patch</div>
                  <div><span className="text-chart-4">void</span> <span className="text-primary">patch_cpuid</span>() {"{"}</div>
                  <div className="pl-4"><span className="text-muted-foreground">// Original: cpuid instruction</span></div>
                  <div className="pl-4"><span className="text-muted-foreground">// Patched: mov eax, "quant" values</span></div>
                  <div>{"}"}</div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="method2" data-testid="content-method2">
            <Card className="border-primary/20" data-testid="card-method2">
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <CardTitle className="font-display text-2xl">Phương Pháp 2: Dịch Ngược QEMU Code</CardTitle>
                  <div className="flex gap-1">
                    {[1, 2, 3, 4, 5].map((star, idx) => (
                      <span key={idx} className="text-destructive text-lg">⭐</span>
                    ))}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3 text-sm uppercase tracking-wider text-muted-foreground">Các Bước Thực Hiện</h4>
                  <ol className="space-y-3">
                    {[
                      { step: "Phân tích QEMU Source", desc: "Tìm code xử lý CPU quantum" },
                      { step: "Xác định CPU Model", desc: "Tìm định nghĩa CPU \"quantum\" trong QEMU" },
                      { step: "Reverse QEMU Binary", desc: "Phân tích QEMU executable" },
                      { step: "Custom Emulation", desc: "Tạo môi trường giả lập quantum CPU" }
                    ].map((item, idx) => (
                      <li key={idx} className="flex gap-3" data-testid={`step-method2-${idx}`}>
                        <Badge variant="outline" className="font-mono shrink-0 h-6">{idx + 1}</Badge>
                        <div>
                          <div className="font-semibold">{item.step}</div>
                          <div className="text-sm text-muted-foreground">{item.desc}</div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <h4 className="font-semibold mb-3 text-sm uppercase tracking-wider text-muted-foreground">Tập Tin QEMU Quan Trọng</h4>
                  <ul className="space-y-2 text-sm font-mono">
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">›</span>
                      <span><code className="bg-muted px-2 py-1 rounded">target/i386/cpu.c</code> - Định nghĩa CPU models</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">›</span>
                      <span><code className="bg-muted px-2 py-1 rounded">target/i386/helper.c</code> - Xử lý CPUID emulation</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-primary mt-1">›</span>
                      <span><code className="bg-muted px-2 py-1 rounded">target/i386/kvm/cpu.c</code> - KVM-specific handling</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-background rounded-md p-4 font-mono text-xs border border-border overflow-x-auto">
                  <div className="text-muted-foreground mb-2">// QEMU CPU definition</div>
                  <div><span className="text-chart-4">static</span> X86CPUDefinition builtin_x86_defs[] = {"{"}</div>
                  <div className="pl-4">{"{"}</div>
                  <div className="pl-8">.name = <span className="text-primary">"quantum"</span>,</div>
                  <div className="pl-8">.vendor = CPUID_VENDOR_INTEL,</div>
                  <div className="pl-8">.features[FEAT_1_EDX] = ...,</div>
                  <div className="pl-4">{"},"}</div>
                  <div>{"}"}</div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="method3" data-testid="content-method3">
            <Card className="border-primary/20" data-testid="card-method3">
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <CardTitle className="font-display text-2xl">Phương Pháp 3: Dynamic Analysis trong QEMU</CardTitle>
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map((star, idx) => (
                      <span key={idx} className="text-chart-4 text-lg">⭐</span>
                    ))}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3 text-sm uppercase tracking-wider text-muted-foreground">Các Bước Thực Hiện</h4>
                  <ol className="space-y-3">
                    {[
                      { step: "Build QEMU Custom", desc: "Thêm CPU type \"quantum\" vào QEMU source" },
                      { step: "QEMU Modification", desc: "Patch QEMU để hỗ trợ quantum CPU" },
                      { step: "Debugging", desc: "Sử dụng QEMU+GDB để phân tích thời gian thực" }
                    ].map((item, idx) => (
                      <li key={idx} className="flex gap-3" data-testid={`step-method3-${idx}`}>
                        <Badge variant="outline" className="font-mono shrink-0 h-6">{idx + 1}</Badge>
                        <div>
                          <div className="font-semibold">{item.step}</div>
                          <div className="text-sm text-muted-foreground">{item.desc}</div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>

                <div className="bg-background rounded-md p-4 font-mono text-xs border border-border overflow-x-auto">
                  <div className="text-muted-foreground mb-2"># Build custom QEMU with quantum CPU</div>
                  <div><span className="text-primary">./configure</span> --target-list=x86_64-softmmu</div>
                  <div><span className="text-primary">make</span> -j$(nproc)</div>
                  <div className="mt-3 text-muted-foreground"># Run with GDB debugging</div>
                  <div><span className="text-primary">qemu-system-x86_64</span> -cpu quantum -s -S binary.elf</div>
                  <div><span className="text-primary">gdb</span> binary.elf -ex <span className="text-chart-4">"target remote :1234"</span></div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
}
