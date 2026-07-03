import type { RuleFunction } from '../types.js';
import { rls001 } from './rls-001.js';
import { rls002 } from './rls-002.js';
import { rls003 } from './rls-003.js';
import { rls004 } from './rls-004.js';
import { rls005 } from './rls-005.js';

/**
 * Registry of all lint rules.
 * Each rule is a function that receives the analyzed schema and returns findings.
 */
export const rules: RuleFunction[] = [
  rls001,
  rls002,
  rls003,
  rls004,
  rls005,
];
