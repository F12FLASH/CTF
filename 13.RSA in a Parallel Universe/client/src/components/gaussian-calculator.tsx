import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Calculator, Plus, X, Hash } from "lucide-react";
import { MathDisplay } from "./math-display";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { GaussianInteger } from "@shared/schema";

export function GaussianCalculator() {
  const [a, setA] = useState({ real: 0, imaginary: 0 });
  const [b, setB] = useState({ real: 0, imaginary: 0 });
  const [result, setResult] = useState<{ value: GaussianInteger; norm?: number } | null>(null);
  const [operation, setOperation] = useState<string>("");
  const { toast } = useToast();

  const formatGaussian = (z: GaussianInteger | undefined | null): string => {
    if (!z) return "0";
    const { real, imaginary } = z;
    if (imaginary === 0) return `${real}`;
    if (real === 0) return `${imaginary}i`;
    const sign = imaginary > 0 ? "+" : "";
    return `${real}${sign}${imaginary}i`;
  };

  const createMutation = (endpoint: string, operationName: string) => ({
    mutationFn: async () => {
      return await apiRequest("POST", endpoint, { a, b });
    },
    onSuccess: (data: any) => {
      setResult({ value: data.result });
      setOperation(operationName);
      toast({ description: `${operationName} completed successfully` });
    },
    onError: () => {
      toast({ variant: "destructive", description: `Failed to perform ${operationName.toLowerCase()}` });
    },
  });

  const addMutation = useMutation(createMutation("/api/gaussian/add", "Addition"));
  const multiplyMutation = useMutation(createMutation("/api/gaussian/multiply", "Multiplication"));

  const normMutation = useMutation({
    mutationFn: async (z: GaussianInteger) => {
      return await apiRequest("POST", "/api/gaussian/norm", { z });
    },
    onSuccess: (data: any) => {
      setResult({ value: data.gaussian, norm: data.norm });
      setOperation("Norm");
      toast({ description: "Norm calculated successfully" });
    },
    onError: () => {
      toast({ variant: "destructive", description: "Failed to calculate norm" });
    },
  });

  const isLoading = addMutation.isPending || multiplyMutation.isPending || normMutation.isPending;

  const NumberInputSection = ({ 
    number, 
    onChange, 
    prefix,
    testId
  }: {
    number: GaussianInteger;
    onChange: (num: GaussianInteger) => void;
    prefix: string;
    testId: string;
  }) => (
    <div className="space-y-4">
      <div className="space-y-3">
        <div>
          <Label htmlFor={`${testId}-real`} className="text-sm font-medium mb-2 block">
            {prefix} - Real Part
          </Label>
          <Input
            id={`${testId}-real`}
            type="number"
            value={number.real}
            onChange={(e) => onChange({ ...number, real: parseFloat(e.target.value) || 0 })}
            className="h-10"
            disabled={isLoading}
            data-testid={`${testId}-real`}
            placeholder="0"
          />
        </div>
        <div>
          <Label htmlFor={`${testId}-imaginary`} className="text-sm font-medium mb-2 block">
            {prefix} - Imaginary Part
          </Label>
          <Input
            id={`${testId}-imaginary`}
            type="number"
            value={number.imaginary}
            onChange={(e) => onChange({ ...number, imaginary: parseFloat(e.target.value) || 0 })}
            className="h-10"
            disabled={isLoading}
            data-testid={`${testId}-imaginary`}
            placeholder="0"
          />
        </div>
      </div>
      <div className="p-4 border rounded-lg bg-muted/30">
        <p className="text-sm font-medium text-muted-foreground mb-2">{prefix}:</p>
        <div className="min-h-[24px] flex items-center">
          <MathDisplay math={formatGaussian(number)} />
        </div>
      </div>
    </div>
  );

  return (
    <Card className="w-full max-w-4xl mx-auto border shadow-sm">
      <CardHeader className="pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Calculator className="w-6 h-6 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl font-bold">Gaussian Integer Calculator</CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Perform arithmetic operations on complex numbers of the form <strong>a + bi</strong>
            </p>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Input Sections */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <NumberInputSection 
            number={a} 
            onChange={setA} 
            prefix="Number A" 
            testId="input-a" 
          />
          <NumberInputSection 
            number={b} 
            onChange={setB} 
            prefix="Number B" 
            testId="input-b" 
          />
        </div>

        {/* Operation Buttons - Thiết kế mới */}
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Add Button */}
            <Button
              onClick={() => addMutation.mutate()}
              variant="default"
              className="h-12 px-4 flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white"
              disabled={isLoading}
              data-testid="button-add"
            >
              <Plus className="w-4 h-4 flex-shrink-0" />
              <span className="font-medium">Add</span>
            </Button>

            {/* Multiply Button */}
            <Button
              onClick={() => multiplyMutation.mutate()}
              variant="default"
              className="h-12 px-4 flex items-center justify-center gap-2 bg-green-600 hover:bg-green-700 text-white"
              disabled={isLoading}
              data-testid="button-multiply"
            >
              <X className="w-4 h-4 flex-shrink-0" />
              <span className="font-medium">Multiply</span>
            </Button>

            {/* Norm A Button */}
            <Button
              onClick={() => normMutation.mutate(a)}
              variant="outline"
              className="h-12 px-4 flex items-center justify-center gap-2 border-2"
              disabled={isLoading}
              data-testid="button-norm-a"
            >
              <Hash className="w-4 h-4 flex-shrink-0" />
              <span className="font-medium">Norm A</span>
            </Button>

            {/* Norm B Button */}
            <Button
              onClick={() => normMutation.mutate(b)}
              variant="outline"
              className="h-12 px-4 flex items-center justify-center gap-2 border-2"
              disabled={isLoading}
              data-testid="button-norm-b"
            >
              <Hash className="w-4 h-4 flex-shrink-0" />
              <span className="font-medium">Norm B</span>
            </Button>
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="flex justify-center">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
                Calculating...
              </div>
            </div>
          )}
        </div>

        {/* Result Display */}
        {result && (
          <div className="p-6 border-2 rounded-xl bg-gradient-to-br from-blue-50 to-white mt-4 animate-in fade-in duration-300">
            <div className="flex items-center gap-3 mb-4">
              <Badge variant="secondary" className="px-3 py-1 text-sm font-medium">
                {operation}
              </Badge>
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            </div>
            
            <div className="space-y-4">
              <div className="text-center p-4 bg-white rounded-lg border shadow-sm">
                <p className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
                  Result
                </p>
                <div className="text-2xl font-bold text-gray-900">
                  <MathDisplay math={formatGaussian(result.value)} />
                </div>
              </div>
              
              {result.norm !== undefined && (
                <div className="text-center p-4 bg-white rounded-lg border shadow-sm">
                  <p className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
                    Norm Value
                  </p>
                  <div className="text-xl font-semibold text-blue-600">
                    <MathDisplay math={`N(${formatGaussian(result.value)}) = ${result.norm}`} />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}