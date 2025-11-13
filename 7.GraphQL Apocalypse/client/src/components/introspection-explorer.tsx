import { ChevronRight, Database, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";

interface IntrospectionExplorerProps {
  isOpen: boolean;
  onToggle: () => void;
}

export function IntrospectionExplorer({ isOpen, onToggle }: IntrospectionExplorerProps) {
  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={onToggle}
        className={`fixed left-4 top-24 z-40 gap-2 transition-all ${isOpen ? 'translate-x-80' : 'translate-x-0'}`}
        data-testid="button-toggle-explorer"
      >
        <ChevronRight className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : 'rotate-0'}`} />
        {isOpen ? 'Ẩn' : 'Hiện'} Explorer
      </Button>

      <aside
        className={`fixed left-0 top-16 bottom-0 w-80 bg-sidebar border-r border-sidebar-border transition-transform duration-300 z-30 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-4 h-full flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <Database className="w-5 h-5 text-sidebar-primary" />
            <h2 className="text-lg font-semibold text-sidebar-foreground">Schema Explorer</h2>
          </div>

          <ScrollArea className="flex-1">
            <div className="space-y-4">
              <Card className="p-4 bg-sidebar-accent/50 border-sidebar-accent-foreground/10">
                <div className="flex items-center gap-2 mb-3">
                  <Search className="w-4 h-4 text-sidebar-primary" />
                  <h3 className="font-semibold text-sm text-sidebar-foreground">Introspection Query</h3>
                </div>
                <pre className="text-xs font-mono text-sidebar-accent-foreground bg-background/30 p-3 rounded overflow-x-auto">
{`query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      description
    }
    queryType {
      name
    }
    mutationType {
      name
    }
  }
}`}
                </pre>
              </Card>

              <div className="space-y-2">
                <h3 className="text-sm font-semibold text-sidebar-foreground mb-3">Các Type Phổ Biến</h3>
                
                <div className="space-y-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full justify-start text-sm font-mono text-sidebar-accent-foreground hover:bg-sidebar-accent"
                    data-testid="button-type-query"
                  >
                    Query
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full justify-start text-sm font-mono text-sidebar-accent-foreground hover:bg-sidebar-accent"
                    data-testid="button-type-mutation"
                  >
                    Mutation
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full justify-start text-sm font-mono text-sidebar-accent-foreground hover:bg-sidebar-accent"
                    data-testid="button-type-user"
                  >
                    User
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full justify-start text-sm font-mono text-destructive hover:bg-destructive/10"
                    data-testid="button-type-hidden"
                  >
                    ??? (Ẩn)
                  </Button>
                </div>
              </div>

              <Card className="p-4 bg-primary/10 border-primary/20">
                <p className="text-xs text-primary-foreground/90">
                  <span className="font-semibold">Gợi ý:</span> Sử dụng <code className="font-mono bg-background/30 px-1 py-0.5 rounded">__type</code> để kiểm tra các type cụ thể và các field của chúng.
                </p>
              </Card>
            </div>
          </ScrollArea>
        </div>
      </aside>
    </>
  );
}
