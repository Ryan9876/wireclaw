import type { Report } from './investigation-result';
import type { Evidence } from './evidence';
import type { components } from './api';
export function validReport(data: unknown): data is Report;
export function validEvidence(data: unknown): data is Evidence;
export function validCase(data: unknown): data is components['schemas']['CaseResponse'];
export function validDeletion(data: unknown): data is components['schemas']['DeletionResponse'];
