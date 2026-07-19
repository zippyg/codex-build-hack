import type { Responses } from "openai/resources/responses/responses";

import { captureResponses, type CaptureOptions } from "../src/index";

declare const responses: Responses;
declare const options: CaptureOptions;

captureResponses(responses, options);
