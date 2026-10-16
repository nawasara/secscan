<?php

namespace Nawasara\Secscan\Tests;

use Nawasara\Secscan\Models\AgentScanFinding;
use PHPUnit\Framework\TestCase;

/**
 * "Lihat kode" (16 Oktober 2026): konteks dari agen >= v0.13.0 ditampilkan
 * bernomor, baris yang cocok ditandai.
 */
class CodeContextTest extends TestCase
{
    private function finding(array $attrs): AgentScanFinding
    {
        return (new AgentScanFinding)->forceFill($attrs);
    }

    public function test_lines_are_numbered_from_context_start_and_match_is_marked(): void
    {
        $lines = $this->finding([
            'matched_context' => "<?php\n\$a = 1;\nfile_put_contents(\$f, \$_POST['c']);",
            'context_start_line' => 40,
            'match_line' => 42,
        ])->codeLines();

        $this->assertSame([40, 41, 42], array_column($lines, 'no'));
        $this->assertSame([false, false, true], array_column($lines, 'match'));
    }

    public function test_old_agents_without_context_give_no_lines(): void
    {
        $this->assertSame([], $this->finding(['matched_line' => 'eval(', 'matched_context' => null])->codeLines());
    }
}
