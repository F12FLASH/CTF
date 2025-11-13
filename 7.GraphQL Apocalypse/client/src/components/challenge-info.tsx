import { useState } from "react";
import { ChevronDown, Target, AlertCircle, Lightbulb } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

export function ChallengeInfo() {
  const [missionOpen, setMissionOpen] = useState(false);
  const [objectivesOpen, setObjectivesOpen] = useState(false);
  const [hintsOpen, setHintsOpen] = useState(false);

  return (
    <div className="container mx-auto px-4 py-12">
      <div className="max-w-4xl mx-auto space-y-4">
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <AlertCircle className="w-6 h-6 text-primary" />
          Thông Tin Thử Thách
        </h2>

        <Collapsible open={missionOpen} onOpenChange={setMissionOpen}>
          <Card className="overflow-hidden border-primary/20">
            <CollapsibleTrigger asChild>
              <Button
                variant="ghost"
                className="w-full justify-between p-6 h-auto hover:bg-card-foreground/5"
                data-testid="button-toggle-mission"
              >
                <div className="flex items-center gap-3">
                  <Target className="w-5 h-5 text-primary" />
                  <span className="text-lg font-semibold">Nhiệm Vụ</span>
                </div>
                <ChevronDown className={`w-5 h-5 transition-transform ${missionOpen ? 'rotate-180' : ''}`} />
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="px-6 pb-6 space-y-3 text-sm text-muted-foreground">
                <p>
                  Bạn đã chặn được một GraphQL endpoint từ một hệ thống mật. Tình báo cho biết
                  dữ liệu quan trọng—bao gồm một flag—đang ẩn trong cơ sở dữ liệu, chỉ có thể truy cập
                  thông qua một mutation đặc biệt không được ghi lại.
                </p>
                <p>
                  Các quản trị viên hệ thống nghĩ rằng họ an toàn bằng cách che giấu tên mutation,
                  nhưng họ đã bỏ quên introspection. Nhiệm vụ của bạn: tận dụng khả năng introspection
                  của GraphQL để ánh xạ toàn bộ schema, khám phá mutation ẩn, và khai thác
                  bất kỳ lỗ hổng type confusion nào để trích xuất flag.
                </p>
              </div>
            </CollapsibleContent>
          </Card>
        </Collapsible>

        <Collapsible open={objectivesOpen} onOpenChange={setObjectivesOpen}>
          <Card className="overflow-hidden border-secondary/20">
            <CollapsibleTrigger asChild>
              <Button
                variant="ghost"
                className="w-full justify-between p-6 h-auto hover:bg-card-foreground/5"
                data-testid="button-toggle-objectives"
              >
                <div className="flex items-center gap-3">
                  <Target className="w-5 h-5 text-secondary" />
                  <span className="text-lg font-semibold">Mục Tiêu</span>
                </div>
                <ChevronDown className={`w-5 h-5 transition-transform ${objectivesOpen ? 'rotate-180' : ''}`} />
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="px-6 pb-6">
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▸</span>
                    <span className="text-muted-foreground">Sử dụng introspection queries để khám phá GraphQL schema</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▸</span>
                    <span className="text-muted-foreground">Xác định tất cả các query và mutation có sẵn</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▸</span>
                    <span className="text-muted-foreground">Phát hiện mutation ẩn để truy cập dữ liệu được bảo vệ</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▸</span>
                    <span className="text-muted-foreground">Khai thác type confusion để vượt qua các hạn chế bảo mật</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▸</span>
                    <span className="text-muted-foreground">Trích xuất flag và nộp để hoàn thành thử thách</span>
                  </li>
                </ul>
              </div>
            </CollapsibleContent>
          </Card>
        </Collapsible>

        <Collapsible open={hintsOpen} onOpenChange={setHintsOpen}>
          <Card className="overflow-hidden border-destructive/20">
            <CollapsibleTrigger asChild>
              <Button
                variant="ghost"
                className="w-full justify-between p-6 h-auto hover:bg-card-foreground/5"
                data-testid="button-toggle-hints"
              >
                <div className="flex items-center gap-3">
                  <Lightbulb className="w-5 h-5 text-destructive" />
                  <span className="text-lg font-semibold">Gợi Ý</span>
                </div>
                <ChevronDown className={`w-5 h-5 transition-transform ${hintsOpen ? 'rotate-180' : ''}`} />
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="px-6 pb-6 space-y-4">
                <div className="p-4 bg-muted/30 rounded-md border border-muted">
                  <p className="text-sm font-semibold mb-2 text-foreground">🔍 Cơ Bản Về Introspection</p>
                  <p className="text-xs text-muted-foreground font-mono">
                    Query __schema để xem tất cả các type. Sử dụng __type(name: "TypeName") để kiểm tra các type cụ thể và các field của chúng.
                  </p>
                </div>

                <div className="p-4 bg-muted/30 rounded-md border border-muted">
                  <p className="text-sm font-semibold mb-2 text-foreground">🎯 Tìm Mutation</p>
                  <p className="text-xs text-muted-foreground font-mono">
                    Kiểm tra __schema.mutationType để khám phá tất cả các mutation operations. Một số có thể có tên đáng ngờ.
                  </p>
                </div>

                <div className="p-4 bg-muted/30 rounded-md border border-muted">
                  <p className="text-sm font-semibold mb-2 text-foreground">⚡ Type Confusion</p>
                  <p className="text-xs text-muted-foreground">
                    Hệ thống type của GraphQL có thể bị khai thác khi input type chấp nhận các giá trị không mong đợi. 
                    Thử truyền các kiểu dữ liệu khác với mong đợi—string, number, object, hoặc null.
                  </p>
                </div>

                <div className="p-4 bg-primary/10 rounded-md border border-primary/20">
                  <p className="text-sm font-semibold mb-2 text-foreground">💡 Hướng Dẫn Chi Tiết</p>
                  <ol className="text-xs text-muted-foreground space-y-2">
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 1:</span>
                      <span>Chạy introspection query để liệt kê tất cả các type trong schema</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 2:</span>
                      <span>Tìm mutationType và kiểm tra các field của nó</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 3:</span>
                      <span>Phát hiện mutation "unlockSecretVault" với input type "AccessKey"</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 4:</span>
                      <span>Kiểm tra cấu trúc của AccessKey input type</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 5:</span>
                      <span>Thử các cách khác nhau để truyền accessKey (string, object với các field khác nhau)</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 6:</span>
                      <span>Phân tích mô tả của mutation và input type để suy ra access code đúng - thường liên quan đến tên lỗ hổng</span>
                    </li>
                    <li className="flex gap-2">
                      <span className="font-semibold text-primary">Bước 7:</span>
                      <span>Nộp flag nhận được để hoàn thành thử thách</span>
                    </li>
                  </ol>
                </div>
              </div>
            </CollapsibleContent>
          </Card>
        </Collapsible>
      </div>
    </div>
  );
}
