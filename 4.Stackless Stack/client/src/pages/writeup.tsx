import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Terminal, Shield, ChevronLeft, BookOpen, Code2, AlertTriangle } from "lucide-react";
import { Link } from "wouter";
import type { WriteupSection } from "@shared/schema";

export default function WriteupPage() {
  const { data: sections = [], isLoading } = useQuery<WriteupSection[]>({
    queryKey: ["/api/writeup/stackless-stack"],
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-4">
          <Terminal className="w-12 h-12 text-primary animate-pulse mx-auto" />
          <p className="font-jetbrains text-muted-foreground">ĐANG TẢI BÀI GIẢI...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="w-full border-b border-border bg-card/30 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              <h1 className="font-orbitron font-bold text-2xl sm:text-3xl text-foreground">
                CTF<span className="text-primary">_</span>PLATFORM
              </h1>
            </div>
            <Link href="/">
              <Button variant="outline" size="sm" className="font-jetbrains" data-testid="button-back-challenge">
                <ChevronLeft className="w-4 h-4 mr-2" />
                QUAY LẠI THỬ THÁCH
              </Button>
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <div className="mb-8 sm:mb-12">
          <div className="flex items-center gap-3 mb-4">
            <BookOpen className="w-8 h-8 text-primary" />
            <h2 className="font-orbitron font-bold text-3xl sm:text-4xl text-foreground">
              STACKLESS STACK
            </h2>
          </div>
          <p className="text-xl text-muted-foreground font-jetbrains mb-6">
            Hướng Dẫn Khai Thác Hoàn Chỉnh
          </p>
          <div className="flex flex-wrap gap-3">
            <Badge variant="outline" className="font-jetbrains text-xs border-destructive/50 text-destructive bg-destructive/10">
              MASTER HACKER
            </Badge>
            <Badge variant="outline" className="font-jetbrains text-xs border-primary/50 text-primary bg-primary/10">
              PWN
            </Badge>
            <Badge variant="outline" className="font-jetbrains text-xs">
              ROP CHAIN
            </Badge>
            <Badge variant="outline" className="font-jetbrains text-xs">
              MPROTECT
            </Badge>
          </div>
        </div>

        <Card className="border-destructive/30 bg-destructive/5 mb-8">
          <CardHeader>
            <CardTitle className="font-orbitron text-lg flex items-center gap-2 text-destructive">
              <AlertTriangle className="w-5 h-5" />
              CẢNH BÁO SPOILER
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-foreground font-jetbrains">
              Bài giải này chứa lời giải hoàn chỉnh cho thử thách. Chỉ tiếp tục nếu bạn muốn xem các bước khai thác đầy đủ.
            </p>
          </CardContent>
        </Card>

        <div className="space-y-8">
          {sections.length === 0 ? (
            <Card className="border-card-border">
              <CardContent className="py-12">
                <p className="text-center text-muted-foreground font-jetbrains">
                  Bài giải đang được chuẩn bị...
                </p>
              </CardContent>
            </Card>
          ) : (
            sections.map((section, index) => (
              <Card key={section.id} className="border-card-border bg-card/50 backdrop-blur-sm" data-testid={`section-${index}`}>
                <CardHeader>
                  <div className="flex items-start gap-4">
                    <div className="flex-shrink-0 w-12 h-12 rounded-md bg-primary/10 border border-primary/30 flex items-center justify-center">
                      <span className="font-orbitron font-bold text-lg text-primary">
                        {section.order}
                      </span>
                    </div>
                    <div className="flex-1">
                      <CardTitle className="font-orbitron text-2xl text-foreground mb-2" data-testid={`text-section-title-${index}`}>
                        {section.title}
                      </CardTitle>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="prose prose-invert max-w-none">
                    <div 
                      className="text-foreground leading-relaxed whitespace-pre-wrap"
                      data-testid={`text-section-content-${index}`}
                    >
                      {section.content}
                    </div>
                  </div>
                  
                  {section.codeBlock && (
                    <>
                      <Separator className="bg-border my-4" />
                      <div className="relative">
                        <div className="absolute top-3 right-3 z-10">
                          <Badge variant="outline" className="font-jetbrains text-xs">
                            {section.language || "code"}
                          </Badge>
                        </div>
                        <div className="bg-background/50 border border-border rounded-md p-6 overflow-x-auto">
                          <pre className="font-jetbrains text-sm text-foreground" data-testid={`code-block-${index}`}>
                            <code>{section.codeBlock}</code>
                          </pre>
                        </div>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </div>

        <div className="mt-12 text-center">
          <Link href="/">
            <Button variant="outline" size="lg" className="font-jetbrains" data-testid="button-back-bottom">
              <ChevronLeft className="w-4 h-4 mr-2" />
              QUAY LẠI THỬ THÁCH
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
