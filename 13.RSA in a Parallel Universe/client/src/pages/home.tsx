import { Header } from "@/components/header";
import { ChallengeDescription } from "@/components/challenge-description";
import { GaussianCalculator } from "@/components/gaussian-calculator";
import { RSASolver } from "@/components/rsa-solver";
import { CodePlayground } from "@/components/code-playground";
import { HintSystem } from "@/components/hint-system";
import { FlagSubmission } from "@/components/flag-submission";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Calculator, Lock, Lightbulb, Flag } from "lucide-react";

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-primary/10 via-background to-accent/10 border-b">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="text-center space-y-4">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium" data-testid="hero-badge">
              <span className="w-2 h-2 bg-primary rounded-full"></span>
              Master Level Cryptography Challenge
            </div>
            <h1 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-foreground to-muted-foreground bg-clip-text text-transparent">
              RSA in a Parallel Universe
            </h1>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Khám phá RSA trên vành số phức Gaussian (ℤ[i]) - một biến thể cực kỳ phức tạp của mã hóa RSA truyền thống
            </p>
          </div>
        </div>
      </div>
      
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            <ChallengeDescription />
          </div>

          {/* Tools Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            <Tabs defaultValue="calculator" className="w-full">
              <TabsList className="w-full grid grid-cols-4 h-auto p-1">
                <TabsTrigger value="calculator" data-testid="tab-calculator" className="flex flex-col items-center gap-1 py-3">
                  <Calculator className="w-4 h-4" />
                  <span className="text-xs">Calc</span>
                </TabsTrigger>
                <TabsTrigger value="solver" data-testid="tab-solver" className="flex flex-col items-center gap-1 py-3">
                  <Lock className="w-4 h-4" />
                  <span className="text-xs">Solver</span>
                </TabsTrigger>
                <TabsTrigger value="hints" data-testid="tab-hints" className="flex flex-col items-center gap-1 py-3">
                  <Lightbulb className="w-4 h-4" />
                  <span className="text-xs">Hints</span>
                </TabsTrigger>
                <TabsTrigger value="submit" data-testid="tab-submit" className="flex flex-col items-center gap-1 py-3">
                  <Flag className="w-4 h-4" />
                  <span className="text-xs">Flag</span>
                </TabsTrigger>
              </TabsList>
              
              <div className="mt-6">
                <TabsContent value="calculator" className="mt-0">
                  <GaussianCalculator />
                </TabsContent>
                
                <TabsContent value="solver" className="mt-0">
                  <RSASolver />
                </TabsContent>
                
                <TabsContent value="hints" className="mt-0">
                  <HintSystem />
                </TabsContent>
                
                <TabsContent value="submit" className="mt-0">
                  <FlagSubmission />
                </TabsContent>
              </div>
            </Tabs>
          </div>
        </div>

        {/* Code Playground */}
        <div className="mt-8">
          <CodePlayground />
        </div>

        {/* Footer */}
        <footer className="mt-16 py-8 border-t">
          <div className="text-center space-y-4">
            <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground" data-testid="footer-status">
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              <span>Hệ thống đang hoạt động bình thường</span>
            </div>
            <p className="text-sm font-medium">
              CTF Cryptography Challenge Platform
            </p>
            <p className="text-xs text-muted-foreground">
              © 2024 Vietnamese CTF Community - Học tập và nghiên cứu mật mã học
            </p>
            <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
              <span>Difficulty: Master ⭐⭐⭐⭐⭐</span>
              <span>•</span>
              <span>Category: Cryptography</span>
              <span>•</span>
              <span>Technology: Gaussian Integers</span>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}
