import { AlertTriangle, Lock, Search } from "lucide-react";
import { Card } from "@/components/ui/card";

export function Hero() {
  return (
    <section className="relative min-h-[50vh] flex items-center justify-center overflow-hidden bg-gradient-to-b from-background via-background to-card pt-16">
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(138,43,226,0.15),transparent_50%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(0,255,255,0.1),transparent_50%)]" />
      </div>
      
      <div className="container mx-auto px-4 py-12 relative z-10">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="inline-block">
            <h1 
              className="text-5xl md:text-7xl font-bold mb-4 glitch-text"
              data-testid="text-title"
            >
              <span className="bg-gradient-to-r from-primary via-secondary to-primary bg-clip-text text-transparent">
                GRAPHQL APOCALYPSE
              </span>
            </h1>
          </div>
          
          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto" data-testid="text-description">
            Thử thách bảo mật mức độ cao - nơi flag ẩn sâu trong GraphQL schema.
            Chỉ những ai thành thạo introspection và khai thác type confusion mới có thể chinh phục.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto mt-8">
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-primary/20 hover-elevate">
              <Search className="w-8 h-8 text-secondary mb-3 mx-auto" />
              <h3 className="font-semibold mb-2 text-card-foreground">Introspection</h3>
              <p className="text-sm text-muted-foreground">Khám phá các mutation ẩn trong GraphQL schema</p>
            </Card>
            
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-destructive/20 hover-elevate">
              <AlertTriangle className="w-8 h-8 text-destructive mb-3 mx-auto" />
              <h3 className="font-semibold mb-2 text-card-foreground">Type Confusion</h3>
              <p className="text-sm text-muted-foreground">Khai thác lỗ hổng trong xử lý kiểu dữ liệu</p>
            </Card>
            
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-primary/20 hover-elevate">
              <Lock className="w-8 h-8 text-primary mb-3 mx-auto" />
              <h3 className="font-semibold mb-2 text-card-foreground">Capture the Flag</h3>
              <p className="text-sm text-muted-foreground">Lấy flag ẩn từ cơ sở dữ liệu</p>
            </Card>
          </div>
        </div>
      </div>
      
      <style>{`
        @keyframes glitch {
          0%, 100% { transform: translate(0); }
          20% { transform: translate(-2px, 2px); }
          40% { transform: translate(-2px, -2px); }
          60% { transform: translate(2px, 2px); }
          80% { transform: translate(2px, -2px); }
        }
        
        .glitch-text {
          animation: glitch 3s infinite;
          animation-timing-function: steps(2, end);
        }
      `}</style>
    </section>
  );
}
