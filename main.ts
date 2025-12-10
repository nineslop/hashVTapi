import { exec } from 'child_process';
import { promisify } from 'util';
import axios, { AxiosError } from 'axios';
import dotenv from 'dotenv';
import path from 'path';

// Загружаем переменные окружения из .env файла
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

// Валидация конфигурации
function validateConfig() {
  const requiredVars = ['VIRUSTOTAL_API_KEY', 'FILE_PATH'];
  const missingVars = requiredVars.filter(
    (varName) => !process.env[varName] || process.env[varName]?.trim() === ''
  );

  if (missingVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingVars.join(', ')}. ` +
      `Please check your .env file at: ${envPath}`
    );
  }
}

async function getFileHash(
  filePath: string,
  algorithm: 'MD5' | 'SHA256' = 'SHA256'
): Promise<string> {
  try {
    console.log(`🔍 Calculating ${algorithm} hash for: ${filePath}`);
    const command = `certutil -hashfile "${filePath}" ${algorithm}`;
    const { stdout } = await execAsync(command, { encoding: 'utf8', timeout: 60000 });
    
    const lines = stdout.split(/\r?\n/);
    const hashLine = lines.find(line => 
      line.trim() !== '' && 
      !line.includes('hash') && 
      !line.includes('certutil')
    );

    if (!hashLine) {
      throw new Error('Could not find hash in certutil output');
    }

    const hash = hashLine
      .trim()
      .replace(/[^a-fA-F0-9]/g, '')
      .toLowerCase();

    const expectedLength = algorithm === 'MD5' ? 32 : 64;
    if (hash.length !== expectedLength) {
      throw new Error(
        `Invalid ${algorithm} hash length. Expected ${expectedLength}, got ${hash.length}`
      );
    }

    return hash;
  } catch (error) {
    const errorMessage = error instanceof Error 
      ? error.message 
      : String(error);
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
    
    const errorMessage = error instanceof Error
      ? error.message
      : String(error);
    
    throw new Error(`⚡ Unexpected error: ${errorMessage}`);
  }
}

export async function analyzeFile(): Promise<void> {
  try {
    validateConfig();

    const apiKey = process.env.VIRUSTOTAL_API_KEY!;
    const filePath = process.env.FILE_PATH!.replace(/\\\\/g, '\\');
    const algorithm = (process.env.HASH_ALGORITHM as 'MD5' | 'SHA256') || 'SHA256';


    console.log(`📂 File path: ${filePath}`);
    
    const hash = await getFileHash(filePath, algorithm);
    console.log(`✅ Hash calculated: ${hash}`);

    const report = await checkVirusTotal(hash, apiKey);

    const stats = report.data.attributes.last_analysis_stats;
    const cleanEngines = stats.harmless + stats.undetected;
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
    const threatPercentage = Math.round((stats.malicious / totalEngines) * 100);

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
    const errorMessage = error instanceof Error
      ? error.message
      : typeof error === 'object' && error !== null && 'message' in error
        ? (error as any).message
        : String(error);
    
    console.error(`\n🔥 CRITICAL ERROR: ${errorMessage}`);
    console.error(`🔧 Check your configuration in: ${envPath}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  analyzeFile();
}