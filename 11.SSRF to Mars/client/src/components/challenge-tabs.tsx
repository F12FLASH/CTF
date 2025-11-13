import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Shield, Target, Lightbulb, BookOpen } from "lucide-react";

export function ChallengeTabs() {
  return (
    <Tabs defaultValue="overview" className="w-full">
      <TabsList className="grid w-full grid-cols-4 mb-6">
        <TabsTrigger value="overview" className="gap-2" data-testid="tab-overview">
          <BookOpen className="w-4 h-4" />
          <span className="hidden sm:inline">Tổng quan</span>
        </TabsTrigger>
        <TabsTrigger value="technical" className="gap-2" data-testid="tab-technical">
          <Shield className="w-4 h-4" />
          <span className="hidden sm:inline">Kỹ thuật</span>
        </TabsTrigger>
        <TabsTrigger value="objectives" className="gap-2" data-testid="tab-objectives">
          <Target className="w-4 h-4" />
          <span className="hidden sm:inline">Mục tiêu</span>
        </TabsTrigger>
        <TabsTrigger value="hints" className="gap-2" data-testid="tab-hints">
          <Lightbulb className="w-4 h-4" />
          <span className="hidden sm:inline">Gợi ý</span>
        </TabsTrigger>
      </TabsList>

      <TabsContent value="overview" className="space-y-4" data-testid="tab-content-overview">
        <Card className="p-6">
          <h3 className="text-lg font-bold mb-4" data-testid="text-tab-heading">Mô tả Thử thách</h3>
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <p className="text-foreground leading-relaxed">
              <strong>SSRF đến Sao Hỏa</strong> là một ứng dụng web cho phép người dùng fetch URL từ máy chủ, 
              nhưng được bảo vệ bằng hệ thống lọc tên miền nghiêm ngặt. Ứng dụng chặn tất cả các tên miền thông thường 
              và đặc biệt chặn các địa chỉ localhost truyền thống.
            </p>
            <p className="text-muted-foreground mt-3">
              Nhiệm vụ của bạn là vượt qua các bộ lọc này và truy cập cờ ẩn tại{" "}
              <code className="px-2 py-0.5 bg-muted rounded text-primary font-mono">
                http://localhost:1337
              </code>
            </p>
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="text-lg font-bold mb-4">Cơ chế Bảo vệ</h3>
          <ul className="space-y-3">
            {[
              { title: 'Lọc Tên miền', desc: 'Chặn tất cả tên miền' },
              { title: 'Danh sách Đen IP', desc: '127.0.0.1, 0.0.0.0, 127.0.0.0/8' },
              { title: 'Khớp Chuỗi', desc: 'Chặn từ khóa "localhost"' },
              { title: 'Phân tích URL', desc: 'Xác thực URL nghiêm ngặt' },
            ].map((item, i) => (
              <li key={i} className="flex items-start gap-3">
                <div className="mt-1 w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                <div>
                  <span className="font-semibold text-foreground">{item.title}:</span>{" "}
                  <span className="text-muted-foreground">{item.desc}</span>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </TabsContent>

      <TabsContent value="technical" className="space-y-4" data-testid="tab-content-technical">
        <Card className="p-6">
          <h3 className="text-lg font-bold mb-4" data-testid="text-techniques-heading">Kỹ thuật Vượt qua</h3>
          <div className="space-y-4">
            {[
              {
                title: 'IPv6 Localhost',
                rating: 3,
                desc: 'Sử dụng biểu diễn IPv6 ::1 thay vì IPv4 127.0.0.1',
                example: 'http://[::1]:1337/',
              },
              {
                title: 'Biểu diễn IP Thay thế',
                rating: 3,
                desc: 'Chuyển đổi 127.0.0.1 sang định dạng thập phân, hex hoặc bát phân',
                example: 'http://2130706433:1337/ (thập phân)',
              },
              {
                title: 'Thủ thuật DNS',
                rating: 4,
                desc: 'Sử dụng tên miền phân giải về localhost',
                example: 'http://localtest.me:1337/',
              },
              {
                title: 'Ký hiệu Rút gọn',
                rating: 2,
                desc: 'Sử dụng định dạng IP viết tắt',
                example: 'http://127.1:1337/',
              },
            ].map((technique, i) => (
              <div key={i} className="bg-muted/50 rounded-md p-4 border border-border">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-semibold text-foreground">{technique.title}</h4>
                  <div className="flex gap-0.5">
                    {Array.from({ length: technique.rating }).map((_, j) => (
                      <div key={j} className="w-1.5 h-1.5 rounded-full bg-primary" />
                    ))}
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-2">{technique.desc}</p>
                <code className="text-xs font-mono bg-background px-2 py-1 rounded border border-border inline-block">
                  {technique.example}
                </code>
              </div>
            ))}
          </div>
        </Card>
      </TabsContent>

      <TabsContent value="objectives" className="space-y-4" data-testid="tab-content-objectives">
        <Card className="p-6">
          <h3 className="text-lg font-bold mb-4" data-testid="text-objectives-heading">Các Mục tiêu Từng bước</h3>
          <ol className="space-y-4">
            {[
              {
                step: 'Trinh sát',
                tasks: [
                  'Kiểm tra bộ lọc với các URL cơ bản',
                  'Xác định các mẫu chặn',
                  'Tìm các phương pháp vượt qua tiềm năng',
                ],
              },
              {
                step: 'Khai thác',
                tasks: [
                  'Thử các biểu diễn IP thay thế',
                  'Kiểm tra IPv6 localhost',
                  'Thử nghiệm với các thủ thuật DNS',
                ],
              },
              {
                step: 'Lấy Flag',
                tasks: [
                  'Vượt qua bộ lọc thành công',
                  'Fetch http://localhost:1337/flag',
                  'Nộp flag',
                ],
              },
            ].map((objective, i) => (
              <li key={i} className="flex gap-4">
                <div className="flex items-center justify-center w-8 h-8 rounded-full bg-primary/20 text-primary font-bold text-sm shrink-0">
                  {i + 1}
                </div>
                <div className="flex-1">
                  <h4 className="font-semibold text-foreground mb-2">{objective.step}</h4>
                  <ul className="space-y-1.5">
                    {objective.tasks.map((task, j) => (
                      <li key={j} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-primary mt-1">•</span>
                        <span>{task}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </li>
            ))}
          </ol>
        </Card>

        <Card className="p-6 bg-terminal-green/5 border-terminal-green/20">
          <h3 className="text-lg font-bold mb-2 text-terminal-green">Tiêu chí Thành công</h3>
          <p className="text-sm text-muted-foreground">
            Thử thách hoàn thành khi bạn lấy được flag từ endpoint được bảo vệ. 
            Flag sẽ có định dạng:{" "}
            <code className="px-2 py-0.5 bg-background rounded text-terminal-green font-mono">
              VNFLAG&#123;...&#125;
            </code>
          </p>
        </Card>
      </TabsContent>

      <TabsContent value="hints" className="space-y-4" data-testid="tab-content-hints">
        <Card className="p-6">
          <h3 className="text-lg font-bold mb-4" data-testid="text-hints-heading">Gợi ý Dần dần</h3>
          <div className="space-y-3">
            {[
              'Bộ lọc chặn tên miền, nhưng địa chỉ IP hoạt động khác',
              'IPv4 không phải là giao thức IP duy nhất - hãy nghĩ đến IPv6',
              'Máy tính có thể hiểu số ở nhiều định dạng: thập phân, hex, bát phân',
              'Một số dịch vụ DNS công khai phân giải về localhost để kiểm thử',
              'Địa chỉ IP có thể được rút gọn khi các octet bằng không',
            ].map((hint, i) => (
              <div key={i} className="flex gap-3 p-3 bg-muted/50 rounded-md border border-border">
                <div className="flex items-center justify-center w-6 h-6 rounded bg-primary/20 text-primary font-bold text-xs shrink-0">
                  {i + 1}
                </div>
                <p className="text-sm text-muted-foreground">{hint}</p>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-6 bg-primary/5 border-primary/20">
          <div className="flex items-center gap-2 mb-2">
            <Lightbulb className="w-5 h-5 text-primary" data-testid="icon-pro-tip" />
            <h3 className="text-lg font-bold text-primary">Mẹo Chuyên nghiệp</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            Hãy thử các payload mẫu trong phần "Payload Mẫu" bên dưới. Mỗi cái minh họa 
            một kỹ thuật vượt qua khác nhau có thể giúp bạn đạt được mục tiêu.
          </p>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
