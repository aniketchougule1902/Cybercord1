import { GoogleGenAI } from "@google/genai";
import { EntityType, InvestigationResult } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export async function analyzeInvestigation(result: any): Promise<string> {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `Analyze the following OSINT investigation data and provide a concise, professional summary of risks and findings.
      
      Data: ${JSON.stringify(result)}
      
      Format: Professional intelligence report summary.`,
    });

    return response.text || "Analysis unavailable.";
  } catch (error) {
    console.error("AI Analysis Error:", error);
    return "Failed to generate AI analysis.";
  }
}

export async function getCopilotResponse(query: string, context: any): Promise<string> {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `You are CyberCord AI Copilot, an expert OSINT and Cybersecurity assistant.
      Current context: ${JSON.stringify(context)}
      User query: ${query}
      
      Provide helpful, technical, and accurate guidance.`,
    });

    return response.text || "I'm sorry, I couldn't process that request.";
  } catch (error) {
    console.error("Copilot Error:", error);
    return "I'm having trouble connecting to my intelligence core.";
  }
}
