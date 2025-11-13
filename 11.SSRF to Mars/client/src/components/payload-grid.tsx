import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Copy, Star, Lightbulb } from "lucide-react";
import type { PayloadExample } from "@shared/schema";

interface PayloadGridProps {
  onPayloadSelect: (url: string) => void;
}

const EXAMPLE_PAYLOADS: PayloadExample[] = [
  {
    id: '1',
    name: 'IPv6 Localhost',
    technique: 'Thay thế IPv6',
    url: 'http://[::1]:1337/',
    description: 'Sử dụng biểu diễn localhost IPv6',
    difficulty: 3,
  },
  {
    id: '2',
    name: 'IP Thập phân',
    technique: 'Làm rối IP',
    url: 'http://2130706433:1337/',
    description: '127.0.0.1 ở định dạng thập phân',
    difficulty: 3,
  },
  {
    id: '3',
    name: 'IP Hex',
    technique: 'Làm rối IP',
    url: 'http://0x7f000001:1337/',
    description: '127.0.0.1 ở định dạng thập lục phân',
    difficulty: 3,
  },
  {
    id: '4',
    name: 'IP Rút gọn',
    technique: 'Thay thế IP',
    url: 'http://127.1:1337/',
    description: 'Ký hiệu localhost rút gọn',
    difficulty: 2,
  },
  {
    id: '5',
    name: 'IP Bát phân',
    technique: 'Làm rối IP',
    url: 'http://0177.0.0.1:1337/',
    description: 'Biểu diễn bát phân',
    difficulty: 3,
  },
  {
    id: '6',
    name: 'Thủ thuật DNS',
    technique: 'Phân giải DNS',
    url: 'http://localtest.me:1337/',
    description: 'Tên miền phân giải về 127.0.0.1',
    difficulty: 4,
  },
];

export function PayloadGrid({ onPayloadSelect }: PayloadGridProps) {
  const handleCopy = async (url: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold" data-testid="text-payloads-heading">Payload Mẫu</h2>
        <Badge variant="outline" className="font-mono" data-testid="badge-payloads-count">
          {EXAMPLE_PAYLOADS.length} Kỹ thuật
        </Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {EXAMPLE_PAYLOADS.map((payload) => (
          <Card
            key={payload.id}
            className="p-4 hover-elevate active-elevate-2 cursor-pointer transition-all"
            onClick={() => onPayloadSelect(payload.url)}
            data-testid={`card-payload-${payload.id}`}
          >
            <div className="space-y-3">
              {/* Header */}
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1">
                  <h3 className="font-semibold text-foreground mb-1" data-testid={`text-payload-name-${payload.id}`}>
                    {payload.name}
                  </h3>
                  <Badge variant="secondary" className="text-xs font-mono" data-testid={`badge-technique-${payload.id}`}>
                    {payload.technique}
                  </Badge>
                </div>
                
                {/* Difficulty stars */}
                <div className="flex gap-0.5">
                  {Array.from({ length: payload.difficulty }).map((_, i) => (
                    <Star
                      key={i}
                      className="w-3 h-3 fill-primary text-primary"
                    />
                  ))}
                </div>
              </div>

              {/* Description */}
              <p className="text-sm text-muted-foreground" data-testid={`text-payload-desc-${payload.id}`}>
                {payload.description}
              </p>

              {/* URL */}
              <div className="bg-muted rounded-md p-2 flex items-center justify-between gap-2 group">
                <code className="text-xs font-mono text-foreground flex-1 truncate" data-testid={`code-url-${payload.id}`}>
                  {payload.url}
                </code>
                <Button
                  data-testid={`button-copy-payload-${payload.id}`}
                  size="icon"
                  variant="ghost"
                  className="h-6 w-6 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={(e) => handleCopy(payload.url, e)}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <div className="bg-muted/50 rounded-md p-4 border border-border flex items-start gap-2">
        <Lightbulb className="w-4 h-4 shrink-0 mt-0.5 text-primary" data-testid="icon-tip" />
        <p className="text-sm text-muted-foreground font-mono">
          Nhấp vào bất kỳ payload nào để tự động điền vào trình fetch URL
        </p>
      </div>
    </div>
  );
}
