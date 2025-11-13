import { BlockMath, InlineMath } from "react-katex";
import "katex/dist/katex.min.css";

interface MathDisplayProps {
  math: string;
  block?: boolean;
  className?: string;
}

export function MathDisplay({ math, block = false, className = "" }: MathDisplayProps) {
  if (block) {
    return (
      <div className={`p-4 border rounded-md bg-card my-4 overflow-x-auto ${className}`} data-testid="math-block">
        <BlockMath math={math} />
      </div>
    );
  }

  return (
    <span className={className} data-testid="math-inline">
      <InlineMath math={math} />
    </span>
  );
}
