import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Play, Copy, Trash2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { QueryResult } from "@shared/schema";
import { CodeEditor } from "@/components/code-editor";

const EXAMPLE_QUERY = `query {
  hello
  users {
    id
    username
  }
}`;

export function QueryEditor() {
  const [query, setQuery] = useState(EXAMPLE_QUERY);
  const [result, setResult] = useState<QueryResult | null>(null);
  const { toast } = useToast();

  const executeMutation = useMutation({
    mutationFn: async (graphqlQuery: string) => {
      const res = await apiRequest("POST", "/api/graphql", { query: graphqlQuery });
      return await res.json() as QueryResult;
    },
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (error: Error) => {
      toast({
        title: "Query Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleExecute = () => {
    executeMutation.mutate(query);
  };

  const handleCopy = async () => {
    if (result) {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      toast({
        title: "Đã Sao Chép!",
        description: "Response đã được sao chép vào clipboard",
      });
    }
  };

  const handleClear = () => {
    setQuery("");
    setResult(null);
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              Trình Soạn Query
            </h2>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={handleClear}
                data-testid="button-clear"
              >
                <Trash2 className="w-4 h-4" />
              </Button>
              <Button
                size="sm"
                onClick={handleExecute}
                disabled={executeMutation.isPending}
                className="gap-2"
                data-testid="button-execute"
              >
                {executeMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                Thực Thi
              </Button>
            </div>
          </div>
          
          <CodeEditor
            value={query}
            onChange={setQuery}
            placeholder="Nhập GraphQL query của bạn vào đây..."
            className="h-[400px] border-primary/20"
            data-testid="input-query"
          />
          
          <div className="text-xs text-muted-foreground space-y-1">
            <p><span className="text-primary font-semibold">Mẹo:</span> Sử dụng introspection queries để khám phá schema</p>
            <p className="font-mono">__schema, __type, __typename</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-secondary animate-pulse" />
              Kết Quả
            </h2>
            {result && (
              <Button
                size="sm"
                variant="outline"
                onClick={handleCopy}
                data-testid="button-copy"
              >
                <Copy className="w-4 h-4" />
              </Button>
            )}
          </div>
          
          <Card className="p-0 overflow-hidden border-secondary/20 bg-card/50 h-[400px]">
            <div className="h-full overflow-auto p-4">
              {executeMutation.isPending ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                </div>
              ) : result ? (
                <pre className="font-mono text-xs text-card-foreground" data-testid="text-response">
                  {JSON.stringify(result, null, 2)}
                </pre>
              ) : (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  <p>Thực thi một query để xem kết quả</p>
                </div>
              )}
            </div>
          </Card>
          
          {result?.errors && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
              <p className="text-sm font-semibold text-destructive mb-2">Lỗi:</p>
              {result.errors.map((error, i) => (
                <p key={i} className="text-xs text-destructive/90 font-mono">
                  {error.message}
                </p>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
