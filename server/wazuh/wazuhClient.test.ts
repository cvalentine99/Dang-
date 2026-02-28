import { describe, it, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import { wazuhGet, type WazuhConfig } from "./wazuhClient";

vi.mock("axios");

describe("wazuhClient sanitization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("keeps key fields from Wazuh API payloads", async () => {
    const mockPost = vi.fn().mockResolvedValue({
      data: { data: { token: "jwt-token", exp: Math.floor(Date.now() / 1000) + 300 } },
    });
    const mockGet = vi.fn().mockResolvedValue({
      data: {
        data: {
          affected_items: [{ key: "linux", count: 11 }],
        },
      },
    });

    vi.mocked(axios.create).mockReturnValue({ post: mockPost, get: mockGet } as any);

    const config: WazuhConfig = {
      host: "192.168.50.158",
      port: 55000,
      user: "wazuh-wui",
      pass: "secret",
    };

    const result = (await wazuhGet(config, { path: "/agents/stats/distinct" })) as any;
    expect(result.data.affected_items[0].key).toBe("linux");
  });
});
