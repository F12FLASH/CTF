import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Circle, Lock } from "lucide-react";
import { MathDisplay } from "./math-display";
import type { SolverStep } from "@shared/schema";

const SOLVER_STEPS: SolverStep[] = [
  {
    id: 1,
    title: "Phân tích modulus n",
    description: "Tìm các Gaussian primes p và q sao cho n = p × q",
    formula: "n = p \\times q",
    completed: false,
  },
  {
    id: 2,
    title: "Tính norm của các prime factors",
    description: "Tính N(p) và N(q) để sử dụng trong bước tiếp theo",
    formula: "N(p) = p_{real}^2 + p_{imag}^2",
    completed: false,
  },
  {
    id: 3,
    title: "Tính φ(n) - Euler's totient",
    description: "Sử dụng công thức cho Gaussian integers",
    formula: "\\phi(n) = (N(p)-1) \\times (N(q)-1)",
    completed: false,
  },
  {
    id: 4,
    title: "Tính khóa bí mật d",
    description: "Tìm modular inverse của e modulo φ(n)",
    formula: "d = e^{-1} \\mod \\phi(n)",
    completed: false,
  },
  {
    id: 5,
    title: "Giải mã ciphertext",
    description: "Áp dụng khóa bí mật để giải mã",
    formula: "m = c^d \\mod n",
    completed: false,
  },
];

export function RSASolver() {
  const [steps, setSteps] = useState<SolverStep[]>(SOLVER_STEPS);
  const [currentStep, setCurrentStep] = useState(0);

  const completeStep = (stepId: number) => {
    setSteps((prev) =>
      prev.map((step) =>
        step.id === stepId ? { ...step, completed: true } : step
      )
    );
    if (stepId < SOLVER_STEPS.length) {
      setCurrentStep(stepId);
    }
  };

  const resetSolver = () => {
    setSteps(SOLVER_STEPS);
    setCurrentStep(0);
  };

  return (
    <Card className="border rounded-lg" data-testid="card-rsa-solver">
      <CardHeader className="p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Lock className="w-6 h-6 text-primary" />
            <CardTitle className="text-xl">RSA Gaussian Solver</CardTitle>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={resetSolver}
            data-testid="button-reset-solver"
          >
            Reset
          </Button>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Follow these steps to solve RSA on Gaussian integers
        </p>
      </CardHeader>
      <CardContent className="p-6 pt-0">
        <div className="space-y-4">
          {steps.map((step, index) => (
            <div
              key={step.id}
              className={`relative border rounded-lg p-4 transition-all duration-200 ${
                step.completed
                  ? "border-primary/50 bg-primary/5"
                  : index === currentStep
                  ? "border-primary bg-card"
                  : "border-border bg-card/50"
              }`}
              data-testid={`step-${step.id}`}
            >
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0 mt-1">
                  {step.completed ? (
                    <CheckCircle2 className="w-6 h-6 text-primary" />
                  ) : (
                    <Circle className="w-6 h-6 text-muted-foreground" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant={step.completed ? "default" : "secondary"}>
                      Bước {step.id}
                    </Badge>
                    <h3 className="text-base font-semibold">{step.title}</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">
                    {step.description}
                  </p>
                  {step.formula && (
                    <div className="bg-muted/30 p-3 rounded-md">
                      <MathDisplay math={step.formula} />
                    </div>
                  )}
                  {!step.completed && index === currentStep && (
                    <Button
                      className="mt-4"
                      size="sm"
                      onClick={() => completeStep(step.id)}
                      data-testid={`button-complete-step-${step.id}`}
                    >
                      Mark as Complete
                    </Button>
                  )}
                </div>
              </div>
              {index < steps.length - 1 && (
                <div
                  className={`absolute left-[21px] top-[60px] w-0.5 h-[calc(100%+16px)] ${
                    step.completed ? "bg-primary/30" : "bg-border"
                  }`}
                />
              )}
            </div>
          ))}
        </div>
        {steps.every((s) => s.completed) && (
          <div className="mt-6 p-4 border border-primary/50 rounded-lg bg-primary/5" data-testid="solver-complete">
            <p className="text-sm font-medium text-primary">
              🎉 Hoàn thành tất cả các bước! Bây giờ bạn có thể submit flag.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
