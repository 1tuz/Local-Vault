import { describe, expect, it } from "vitest";
import { ApiError } from "~/services/http.client";
import { nameErrorMessage } from "./name-errors";

describe("nameErrorMessage", () => {
  it("explains display-name validation instead of showing a generic failure", () => {
    expect(
      nameErrorMessage(
        new ApiError(422, {
          PROJECT_NAME_INVALID:
            "Project name must contain 1 to 128 characters and no control characters.",
        }),
      ),
    ).toBe("Use 1–128 characters. Control characters are not allowed.");
  });
});
