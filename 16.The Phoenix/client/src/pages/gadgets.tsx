import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Copy, Search, AlertCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import type { OneGadget } from "@shared/schema";
import { Skeleton } from "@/components/ui/skeleton";
import { useLanguage } from "@/components/app-sidebar";
import { Alert, AlertDescription } from "@/components/ui/alert";

export default function Gadgets() {
  const { toast } = useToast();
  const { lang } = useLanguage();
  const [searchQuery, setSearchQuery] = useState("");
  const [libcFilter, setLibcFilter] = useState("all");

  const { data: gadgets = [], isLoading, error } = useQuery<OneGadget[]>({
    queryKey: ["/api/gadgets"],
  });

  const filteredGadgets = gadgets.filter((gadget) => {
    const matchesSearch =
      searchQuery === "" ||
      gadget.address.toLowerCase().includes(searchQuery.toLowerCase()) ||
      gadget.constraints.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesLibc =
      libcFilter === "all" || gadget.libcVersion === libcFilter;
    return matchesSearch && matchesLibc;
  });

  const libcVersions = Array.from(new Set(gadgets.map((g) => g.libcVersion)));

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: lang === "vi" ? "Đã Sao Chép!" : "Copied!",
      description: lang === "vi" ? "Địa chỉ đã được sao chép" : "Address copied to clipboard",
    });
  };

  return (
    <div className="p-4 lg:p-6 space-y-4 lg:space-y-6 h-full overflow-y-auto">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold">
          {lang === "vi" ? "Cơ Sở Dữ Liệu One-Gadget" : "One-Gadget Database"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {lang === "vi" 
            ? "Gadget RCE cho các phiên bản libc phổ biến"
            : "RCE gadgets for common libc versions"}
        </p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {lang === "vi" 
              ? "Không thể tải gadgets. Vui lòng thử lại."
              : "Failed to load gadgets. Please try again."}
          </AlertDescription>
        </Alert>
      )}

      <Card className="p-4">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={lang === "vi" 
                ? "Tìm kiếm theo địa chỉ hoặc ràng buộc..."
                : "Search by address or constraints..."}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
              data-testid="input-search-gadgets"
            />
          </div>
          <Select value={libcFilter} onValueChange={setLibcFilter}>
            <SelectTrigger className="w-full md:w-64" data-testid="select-libc-filter">
              <SelectValue placeholder={lang === "vi" ? "Lọc theo phiên bản libc" : "Filter by libc version"} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">
                {lang === "vi" ? "Tất Cả Phiên Bản" : "All Versions"}
              </SelectItem>
              {libcVersions.map((version) => (
                <SelectItem key={version} value={version}>
                  {version}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </Card>

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {filteredGadgets.length === 0 ? (
            <Card className="p-12 text-center">
              <p className="text-sm text-muted-foreground">
                {lang === "vi"
                  ? "Không tìm thấy gadget nào phù hợp với tiêu chí của bạn"
                  : "No gadgets found matching your criteria"}
              </p>
            </Card>
          ) : (
            filteredGadgets.map((gadget, index) => (
              <Card key={gadget.id} className="p-4 hover-elevate">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-4 w-full">
                    <div className="space-y-1">
                      <span className="text-xs text-muted-foreground uppercase tracking-wide">
                        {lang === "vi" ? "Địa Chỉ" : "Address"}
                      </span>
                      <div className="font-mono text-sm font-semibold" data-testid={`gadget-address-${index}`}>
                        {gadget.address}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-xs text-muted-foreground uppercase tracking-wide">
                        {lang === "vi" ? "Ràng Buộc" : "Constraints"}
                      </span>
                      <div className="font-mono text-xs" data-testid={`gadget-constraints-${index}`}>
                        {gadget.constraints}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-xs text-muted-foreground uppercase tracking-wide">
                        {lang === "vi" ? "Phiên Bản Libc" : "Libc Version"}
                      </span>
                      <Badge variant="secondary" className="font-mono text-xs">
                        {gadget.libcVersion}
                      </Badge>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(gadget.address)}
                    data-testid={`button-copy-gadget-${index}`}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
