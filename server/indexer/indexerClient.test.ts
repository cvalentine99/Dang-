import { describe, it, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import { indexerSearch, type IndexerConfig } from "./indexerClient";

vi.mock("axios");

describe("indexerClient sanitization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("preserves aggregation bucket keys used by dashboards", async () => {
    const mockPost = vi.fn().mockResolvedValue({
      data: {
        aggregations: {
          levels: {
            buckets: [
              { key: 12, doc_count: 5 },
              { key: 7, doc_count: 9 },
            ],
          },
        },
      },
    });

    vi.mocked(axios.create).mockReturnValue({ post: mockPost } as any);

    const config: IndexerConfig = {
      host: "192.168.50.158",
      port: 9200,
      user: "admin",
      pass: "secret",
      protocol: "https",
    };

    const result = await indexerSearch(config, "wazuh-alerts-*", { size: 0, aggs: {} });
    const buckets = (result.aggregations as any).levels.buckets;

    expect(buckets[0].key).toBe(12);
    expect(buckets[1].key).toBe(7);
  });
});
