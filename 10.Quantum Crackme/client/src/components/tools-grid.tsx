import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Wrench, Server, Cpu, GraduationCap } from "lucide-react";

export function ToolsGrid() {
  const toolCategories = [
    {
      icon: Wrench,
      title: "Reverse Engineering",
      color: "text-primary",
      bgColor: "bg-primary/10",
      tools: [
        { name: "IDA Pro/Ghidra", desc: "Phân tích binary" },
        { name: "Binary Ninja", desc: "Dynamic analysis" },
        { name: "x64dbg/OllyDbg", desc: "Debugging trên Windows" }
      ]
    },
    {
      icon: Server,
      title: "QEMU Analysis",
      color: "text-chart-2",
      bgColor: "bg-chart-2/10",
      tools: [
        { name: "QEMU Source Code", desc: "Phân tích và sửa đổi" },
        { name: "GDB + QEMU", desc: "Remote debugging" },
        { name: "Custom Scripts", desc: "Tự động hóa phân tích" }
      ]
    },
    {
      icon: Cpu,
      title: "Low-level Tools",
      color: "text-chart-3",
      bgColor: "bg-chart-3/10",
      tools: [
        { name: "CPUID Dumper", desc: "Phân tích CPU capabilities" },
        { name: "Hex Editors", desc: "Binary patching" },
        { name: "Assembly Debuggers", desc: "Low-level execution tracing" }
      ]
    },
    {
      icon: GraduationCap,
      title: "Kỹ Năng Yêu Cầu",
      color: "text-destructive",
      bgColor: "bg-destructive/10",
      tools: [
        { name: "x86 Architecture", desc: "Instruction set và assembly" },
        { name: "QEMU Internals", desc: "CPU emulation knowledge" },
        { name: "Binary Reversing", desc: "Thành thạo reverse engineering" }
      ]
    }
  ];

  return (
    <section className="py-16 lg:py-24 bg-muted/30">
      <div className="max-w-7xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Công Cụ & <span className="text-primary">Yêu Cầu</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {toolCategories.map((category, idx) => {
            const Icon = category.icon;
            return (
              <Card key={idx} className="hover-elevate border-primary/10" data-testid={`card-tools-${idx}`}>
                <CardHeader>
                  <div className={`w-12 h-12 rounded-lg ${category.bgColor} flex items-center justify-center mb-3`}>
                    <Icon className={`w-6 h-6 ${category.color}`} />
                  </div>
                  <CardTitle className="text-lg font-display">{category.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-3">
                    {category.tools.map((tool, toolIdx) => (
                      <li key={toolIdx} className="border-l-2 border-primary/30 pl-3" data-testid={`tool-${idx}-${toolIdx}`}>
                        <div className="font-semibold text-sm font-mono">{tool.name}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{tool.desc}</div>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </section>
  );
}
