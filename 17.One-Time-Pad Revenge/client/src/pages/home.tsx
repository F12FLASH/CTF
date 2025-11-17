import { Header } from "@/components/header";
import { HeroSection } from "@/components/hero-section";
import { EncryptionSimulator } from "@/components/encryption-simulator";
import { CiphertextUpload } from "@/components/ciphertext-upload";
import { StatisticalAnalysis } from "@/components/statistical-analysis";
import { XorAnalysisViewer } from "@/components/xor-analysis-viewer";
import { KnownPlaintextAttack } from "@/components/known-plaintext-attack";
import { FlagVerification } from "@/components/flag-verification";
import { EducationalWalkthrough } from "@/components/educational-walkthrough";
import { ChallengeGenerator } from "@/components/challenge-generator";

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <HeroSection />
      
      <div className="h-20 border-b bg-card/50 backdrop-blur-sm sticky top-16 z-40">
        <div className="container mx-auto h-full px-6 flex items-center">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 w-full text-center">
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Loại Thử Thách
              </p>
              <p className="font-mono font-medium">Phân Tích Mật Mã</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Vectơ Tấn Công
              </p>
              <p className="font-mono font-medium">Tái Sử Dụng Key</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Kỹ Thuật
              </p>
              <p className="font-mono font-medium">Thống Kê</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                Trạng Thái
              </p>
              <p className="font-mono font-medium text-primary">Đang Hoạt Động</p>
            </div>
          </div>
        </div>
      </div>

      <main className="container mx-auto px-6 py-12 space-y-12" id="analysis-tools">
        <div className="grid lg:grid-cols-3 gap-8">
          <div className="space-y-8">
            <ChallengeGenerator />
            <EncryptionSimulator />
            <CiphertextUpload />
          </div>

          <div className="lg:col-span-2 space-y-8">
            <StatisticalAnalysis />
            <XorAnalysisViewer />
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          <KnownPlaintextAttack />
          <FlagVerification />
        </div>

        <EducationalWalkthrough />
      </main>

      <footer className="h-32 border-t bg-card/30 mt-24">
        <div className="container mx-auto h-full px-6 flex flex-col justify-center">
          <div className="text-center space-y-2">
            <p className="text-sm text-muted-foreground">
              Nền Tảng Thử Thách CTF Mật Mã - Báo Thù One-Time-Pad
            </p>
            <p className="text-xs text-muted-foreground">
              Công cụ giáo dục để học các kỹ thuật phân tích mật mã nâng cao
            </p>
            <p className="text-xs text-muted-foreground">
              Sử dụng các công cụ phân tích để khôi phục keystream và tìm flag
            </p>
            <p className="text-xs text-muted-foreground">
              Cẩn thận bị lừa nhé! HEHE
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
