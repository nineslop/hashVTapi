import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import dotenv from 'dotenv';
import path from 'path';

const envPath = path.resolve(__dirname, '.env');
dotenv.config({ path: envPath });

const execAsync = promisify(exec);

interface VirusTotalData {
  attributes: {
    last_analysis_stats: {
      malicious: number;
      suspicious: number;
      undetected: number;
      harmless: number;
    };
    meaningful_name?: string;
    type_description?: string;
  };
}

interface VirusTotalReport {
  data: VirusTotalData;
}

function validateConfig() {
  const requiredVars = ['VIRUSTOTAL_API_KEY', 'FILE_PATH'];
  const missingVars = requiredVars.filter(
    varName => !process.env[varName] || process.env[varName]?.trim() === ''
  );

  if (missingVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingVars.join(', ')}. ` +
      `Check your .env file at: ${envPath}`
    );
  }
}

async function getFileHash(
  filePath: string,
  algorithm: 'MD5' | 'SHA256' = 'SHA256'
): Promise<string> {
  try {
    console.log(`🔍 Calculating ${algorithm} hash for: ${filePath}`);
    
    const safePath = filePath.replace(/"/g, '');
    const command = `certutil -hashfile "${safePath}" ${algorithm}`;
    
    console.log(`⚙️ Running command: ${command}`);
    
    const { stdout, stderr } = await execAsync(command, { 
      encoding: 'utf8',
      timeout: 60000
    });
    
    if (stderr) {
      console.warn(`⚠️ certutil stderr: ${stderr}`);
    }
    
    console.log(`📋 certutil output:\n${stdout}`);
    
    const lines = stdout.split(/\r?\n/).map(line => line.trim());
    const hashLines = lines.filter(line => 
      line && 
      !line.toLowerCase().includes('hash') && 
      !line.toLowerCase().includes('certutil') &&
      line.length > 10
    );
    
    if (hashLines.length === 0) {
      throw new Error('No valid hash line found in certutil output');
    }
    
    let hash = hashLines[0]
      .replace(/[^a-fA-F0-9]/g, '')
      .toLowerCase();
    
    console.log(`🔧 Raw hash extracted: "${hashLines[0]}" → cleaned: "${hash}"`);
    
    const expectedLength = algorithm === 'MD5' ? 32 : 64;
    
    if (hash.length < expectedLength && lines.length > 2) {
      console.log('🔍 Searching for hash in additional lines...');
      for (let i = 1; i < lines.length; i++) {
        const candidate = lines[i].replace(/[^a-fA-F0-9]/g, '').toLowerCase();
        if (candidate.length >= expectedLength - 5) {
          hash = candidate;
          console.log(`✅ Found potential hash in line ${i + 1}: "${hash}"`);
          break;
        }
      }
    }
    
    if (hash.length !== expectedLength) {
      throw new Error(
        `Invalid ${algorithm} hash length. Expected ${expectedLength}, got ${hash.length}. ` +
        `Raw output was: "${hashLines[0]}"`
      );
    }
    
    return hash;
  } catch (error) {
    let errorMessage = 'Unknown error';
    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === 'string') {
      errorMessage = error;
    }
    
    throw new Error(`Hash calculation failed: ${errorMessage}`);
  }
}

async function checkVirusTotal(
  hash: string,
  apiKey: string
): Promise<VirusTotalReport> {
  const url = `https://www.virustotal.com/api/v3/files/${hash}`;
  
  try {
    console.log('☁️ Checking on VirusTotal...');
    const response = await axios.get<VirusTotalReport>(url, {
      headers: {
        'x-apikey': apiKey,
        'accept': 'application/json'
      },
      timeout: 15000
    });

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 404) {
        throw new Error('❌ File not found in VirusTotal database');
      }
      
      const errorMessage = error.response?.data?.error?.message 
        || error.response?.statusText
        || error.message;
      
      throw new Error(
        `🌐 VirusTotal API error (${error.response?.status || 'unknown status'}): ${errorMessage}`
      );
    }
    
    let errorMessage = 'Unknown error';
    if (error instanceof Error) {
      errorMessage = error.message;
    }
    
    throw new Error(`⚡ Unexpected error: ${errorMessage}`);
  }
}

export async function analyzeFile(): Promise<void> {
  try {
    validateConfig();

    const apiKey = process.env.VIRUSTOTAL_API_KEY!;
    const filePath = process.env.FILE_PATH!
      .replace(/\\\\/g, '\\')
      .replace(/^"|"$/g, '');
    const algorithm = (process.env.HASH_ALGORITHM as 'MD5' | 'SHA256') || 'SHA256';

    console.log(`📂 Cleaned file path: ${filePath}`);
    
    try {
      const { stdout } = await execAsync(`powershell -Command "Test-Path '${filePath}'"`, {
        timeout: 5000
      });
      if (!stdout.trim().toLowerCase().includes('true')) {
        console.warn('⚡ File existence check failed - continuing anyway (path might be valid)');
      }
    } catch (e) {
      console.warn('⚠️ Could not verify file existence:', e instanceof Error ? e.message : String(e));
    }

    const hash = await getFileHash(filePath, algorithm);
    console.log(`✅ Final hash: ${hash}`);

    const report = await checkVirusTotal(hash, apiKey);

    const stats = report.data.attributes.last_analysis_stats;
    const cleanEngines = stats.harmless + stats.undetected;
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
    const threatPercentage = totalEngines > 0 ? Math.round((stats.malicious / totalEngines) * 100) : 0;

    console.log('\n' + '='.repeat(50));
    console.log('🛡️  VIRUSTOTAL ANALYSIS REPORT');
    console.log('='.repeat(50));
    console.log(`🔤 File name: ${report.data.attributes.meaningful_name || 'Unknown'}`);
    console.log(`.mime File type: ${report.data.attributes.type_description || 'Unknown'}`);
    console.log(`🔗 Permalink: https://www.virustotal.com/gui/file/${hash}`);
    console.log('-'.repeat(50));
    console.log(`🔴 Malicious:  ${stats.malicious} (${threatPercentage}%)`);
    console.log(`🟠 Suspicious: ${stats.suspicious}`);
    console.log(`🟢 Clean:      ${cleanEngines}`);
    console.log(`❓ Undetected: ${stats.undetected}`);
    console.log('-'.repeat(50));
    
    if (stats.malicious > 0) {
      console.log(`\n🚨 SECURITY ALERT: ${stats.malicious} engines detected threats!`);
      console.log('⚠️  This file is likely malicious. Do not execute!');
    } else if (stats.suspicious > 0) {
      console.log(`\n🟡 CAUTION: ${stats.suspicious} engines flagged this file as suspicious.`);
      console.log('🔍 Further manual analysis recommended.');
    } else {
      console.log('\n✅ VERDICT: No threats detected by security vendors');
    }
    
    console.log('='.repeat(50));
  } catch (error) {
    let errorMessage = 'Unknown error';
    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === 'object' && error !== null && 'message' in error) {
      errorMessage = (error as any).message;
    } else if (typeof error === 'string') {
      errorMessage = error;
    }
    
    console.error(`\n🔥 CRITICAL ERROR: ${errorMessage}`);
    console.error(`🔧 Check your configuration in: ${envPath}`);
    console.error(`📄 Current .env content:`);
    console.error(`VIRUSTOTAL_API_KEY=${process.env.VIRUSTOTAL_API_KEY ? '***HIDDEN***' : 'MISSING'}`);
    console.error(`FILE_PATH=${process.env.FILE_PATH}`);
    console.error(`HASH_ALGORITHM=${process.env.HASH_ALGORITHM || 'SHA256'}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  analyzeFile();
}