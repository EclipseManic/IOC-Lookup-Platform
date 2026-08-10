import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import SearchBar from "../SearchBar";

describe("SearchBar", () => {
  it.each(["eclipsemanic.me", "2606:4700:4700::1111", "hxxps://example[.]com/"])(
    "submits %s to the backend classifier",
    (value) => {
      const onSearch = vi.fn();
      render(<SearchBar onSearch={onSearch} />);

      fireEvent.change(screen.getByLabelText("Search IOC"), { target: { value } });
      fireEvent.click(screen.getByLabelText("Submit search"));

      expect(onSearch).toHaveBeenCalledWith(value);
      expect(screen.queryByText("Unrecognized IOC format")).toBeNull();
    },
  );
});
