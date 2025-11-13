import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BookOpen, ExternalLink, Shield } from "lucide-react";

export function EducationalSidebar() {
  const resources = [
    {
      title: "JWT Algorithm Confusion",
      description: "Hiểu về lỗ hổng RS256/HS256",
      url: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    },
    {
      title: "JWT Security Best Practices",
      description: "Cách triển khai JWT an toàn",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    },
    {
      title: "CVE-2016-5431 Details",
      description: "Chi tiết về lỗ hổng này",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2016-5431",
    },
  ];

  return (
    <Card className="border-chart-2/30 bg-card/50 backdrop-blur-sm" data-testid="card-educational">
      <CardHeader className="pb-4">
        <CardTitle className="text-lg font-mono flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-chart-2" />
          Tài Liệu Tham Khảo
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {resources.map((resource, index) => (
          <a
            key={index}
            href={resource.url}
            target="_blank"
            rel="noopener noreferrer"
            className="block p-3 bg-secondary/30 border border-border rounded-md hover-elevate active-elevate-2 transition-colors"
            data-testid={`link-resource-${index}`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="space-y-1">
                <h4 className="font-mono text-sm font-medium text-foreground">
                  {resource.title}
                </h4>
                <p className="font-mono text-xs text-muted-foreground">
                  {resource.description}
                </p>
              </div>
              <ExternalLink className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
            </div>
          </a>
        ))}

        <div className="pt-3 border-t border-border space-y-3">
          <div>
            <h4 className="font-mono text-xs font-medium text-foreground mb-2 flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Giải Thích Lỗ Hổng
            </h4>
            <p className="font-mono text-xs text-muted-foreground leading-relaxed">
              Lỗ hổng Algorithm Confusion xảy ra khi máy chủ chấp nhận nhiều thuật toán JWT mà không kiểm tra chặt chẽ. 
              Kẻ tấn công có thể thay đổi thuật toán từ RS256 (bất đối xứng) sang HS256 (đối xứng) và sử dụng khóa công khai 
              RS256 làm secret HS256 để giả mạo token hợp lệ.
            </p>
          </div>
          
          <div>
            <h4 className="font-mono text-xs font-medium text-foreground mb-2">Các Bước Khai Thác:</h4>
            <ol className="space-y-1 font-mono text-xs text-muted-foreground">
              <li className="flex gap-2">
                <span className="text-primary shrink-0">1.</span>
                <span>Lấy token RS256 ban đầu từ máy chủ</span>
              </li>
              <li className="flex gap-2">
                <span className="text-primary shrink-0">2.</span>
                <span>Giải mã để xem cấu trúc header và payload</span>
              </li>
              <li className="flex gap-2">
                <span className="text-primary shrink-0">3.</span>
                <span>Thay đổi header.alg thành "HS256"</span>
              </li>
              <li className="flex gap-2">
                <span className="text-primary shrink-0">4.</span>
                <span>Sửa payload: role="admin", level=99</span>
              </li>
              <li className="flex gap-2">
                <span className="text-primary shrink-0">5.</span>
                <span>Ký lại bằng HS256 với khóa công khai làm secret</span>
              </li>
              <li className="flex gap-2">
                <span className="text-primary shrink-0">6.</span>
                <span>Gửi token đã giả mạo để chiếm flag</span>
              </li>
            </ol>
          </div>

          <div>
            <h4 className="font-mono text-xs font-medium text-foreground mb-2">Công Cụ Gợi Ý:</h4>
            <p className="font-mono text-xs text-muted-foreground leading-relaxed">
              • <strong>jwt.io</strong> - Công cụ trực tuyến để giải mã/mã hóa JWT
              <br />
              • <strong>jsonwebtoken (Node.js)</strong> - Thư viện để tạo/xác minh JWT
              <br />
              • <strong>PyJWT (Python)</strong> - Thư viện JWT cho Python
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
