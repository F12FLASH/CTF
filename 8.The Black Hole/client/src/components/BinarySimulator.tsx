import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Terminal, Send, Trash2 } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";

interface OutputLine {
  type: "input" | "output" | "system";
  content: string;
}

export function BinarySimulator() {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState<OutputLine[]>([
    { type: "system", content: "Binary loaded: ./blackhole" },
    { type: "system", content: "Seccomp filter active: read, write, exit only" },
    { type: "output", content: "Welcome to The Black Hole" },
    { type: "output", content: "Enter your input:" },
  ]);
  const { t } = useLanguage();

  const handleSend = () => {
    if (!input.trim()) return;

    const newOutput: OutputLine[] = [...output, { type: "input", content: `$ ${input}` }];

    if (input.includes("%p") || input.includes("%x")) {
      newOutput.push(
        { type: "output", content: "0x7ffd5e3d1a20 0x7f8b4c3e2000 0x5621a3f4b010 0x7f8b4c5e7b97" },
        { type: "system", content: "[!] Format string vulnerability detected" },
        { type: "system", content: "[*] Leaked addresses: stack, libc, heap, binary base" }
      );
    } else if (input.toLowerCase().includes("exit")) {
      newOutput.push(
        { type: "system", content: "[*] Preparing exit() call..." },
        { type: "system", content: "[!] exit@GOT: 0x404028 -> 0x7f8b4c5e7cf5 (syscall gadget)" },
        { type: "system", content: "[*] Registers: rax=0x3b rdi=0x7f8b4c6a8d88 ('/bin/sh')" },
        { type: "system", content: "[*] Executing syscall..." },
        { type: "output", content: "$ " },
        { type: "system", content: "[✓] Shell spawned! Use 'cat flag.txt' to get the flag" },
        { type: "system", content: "[i] Hint: Submit the flag through the Flag Submission form below" }
      );
    } else if (input.toLowerCase().includes("cat") && input.toLowerCase().includes("flag")) {
      newOutput.push(
        { type: "system", content: "[!] This is a simulation - flag is not directly visible here" },
        { type: "system", content: "[i] Complete the exploit properly and submit the flag below" },
        { type: "system", content: "[*] Hint: The flag format is VNFLAG{...}" }
      );
    } else if (input.includes("fmtstr") || input.toLowerCase().includes("got")) {
      newOutput.push(
        { type: "output", content: "GOT Table:" },
        { type: "output", content: "  exit@GOT:   0x404028 = 0x7f8b4c3e2890 (libc_exit)" },
        { type: "output", content: "  write@GOT:  0x404030 = 0x7f8b4c3f1270 (libc_write)" },
        { type: "output", content: "  read@GOT:   0x404038 = 0x7f8b4c3f1150 (libc_read)" },
        { type: "system", content: "[*] Target: Overwrite exit@GOT with syscall gadget address" }
      );
    } else {
      newOutput.push({ type: "output", content: `echo: ${input}` });
    }

    setOutput(newOutput);
    setInput("");
  };

  const handleClear = () => {
    setOutput([
      { type: "system", content: "Binary loaded: ./blackhole" },
      { type: "system", content: "Seccomp filter active: read, write, exit only" },
      { type: "output", content: "Welcome to The Black Hole" },
      { type: "output", content: "Enter your input:" },
    ]);
  };

  const getLineColor = (type: OutputLine["type"]) => {
    switch (type) {
      case "input":
        return "text-primary";
      case "system":
        return "text-accent";
      case "output":
        return "text-foreground";
    }
  };

  return (
    <section className="container mx-auto px-4 py-12">
      <div className="mb-8">
        <h2 className="font-heading text-3xl font-bold tracking-tight mb-2" data-testid="text-simulator-title">
          {t("Binary Simulator", "Mô phỏng Binary")}
        </h2>
        <p className="text-muted-foreground" data-testid="text-simulator-description">
          {t("Interactive terminal to test format string payloads and observe behavior", "Terminal tương tác để kiểm tra payload format string và quan sát hành vi")}
        </p>
      </div>

      <Card className="bg-muted/30">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-lg" data-testid="text-terminal-title">
              <Terminal className="h-5 w-5 text-primary" />
              {t("Terminal", "Terminal")}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="font-mono text-xs" data-testid="badge-terminal-status">
                <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-primary" />
                {t("Running", "Đang chạy")}
              </Badge>
              <Button variant="ghost" size="sm" onClick={handleClear} className="gap-2" data-testid="button-clear-terminal">
                <Trash2 className="h-4 w-4" />
                {t("Clear", "Xóa")}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div
              className="min-h-[300px] max-h-[400px] overflow-y-auto rounded-md bg-background/50 p-4 font-mono text-sm"
              data-testid="terminal-output"
            >
              {output.map((line, idx) => (
                <div key={idx} className={`${getLineColor(line.type)} mb-1 leading-relaxed`}>
                  {line.content}
                </div>
              ))}
            </div>

            <div className="flex gap-2">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSend()}
                placeholder={t("Type command or payload...", "Nhập lệnh hoặc payload...")}
                className="flex-1 font-mono"
                data-testid="input-terminal"
              />
              <Button onClick={handleSend} className="gap-2" data-testid="button-send-command">
                <Send className="h-4 w-4" />
                {t("Send", "Gửi")}
              </Button>
            </div>

            <div className="flex flex-wrap gap-2">
              <Badge
                variant="secondary"
                className="cursor-pointer hover-elevate"
                onClick={() => setInput("%p %p %p %p")}
                data-testid="badge-example-leak"
              >
                {t("Example: Leak addresses", "Ví dụ: Rò rỉ địa chỉ")}
              </Badge>
              <Badge
                variant="secondary"
                className="cursor-pointer hover-elevate"
                onClick={() => setInput("exit")}
                data-testid="badge-example-exit"
              >
                {t("Example: Trigger exit", "Ví dụ: Kích hoạt exit")}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
