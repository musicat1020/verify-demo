import vp from './vp.json';
import issuerDidDocument from './issuerDidDocument.json';
import holderDidDocument from './holderDidDocument.json';
import dotenv from 'dotenv';
import { verifyVp } from './verify';

dotenv.config();

const result = verifyVp(vp, holderDidDocument, issuerDidDocument)
console.log(result)