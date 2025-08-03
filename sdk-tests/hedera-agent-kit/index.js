// Loading in env file
import dotenv from 'dotenv';
dotenv.config();

import { ChatOpenAI } from '@langchain/openai';
import { ChatPromptTemplate } from '@langchain/core/prompts';
import { AgentExecutor, createToolCallingAgent } from 'langchain/agents';
import { Client, PrivateKey } from '@hashgraph/sdk';
import { HederaLangchainToolkit } from 'hedera-agent-kit';


async function main() {
    // Initialise OpenAI LLM model to feed into langchain agent
    const llm = new ChatOpenAI({
        model: 'gpt-4o-mini',
    });

    // Creates a Hedera client (Testnet by default) using hedera testnet account details and keys
    //Hedera is movign from ED25519 to ECDSA keys 
    const client = Client.forTestnet().setOperator(
        process.env.ACCOUNT_ID,
        PrivateKey.fromStringDer(process.env.PRIVATE_KEY),
    );

    const hederaAgentToolkit = new HederaLangchainToolkit({
        client,
        configuration: {
            tools: [] // use an empty array if you want to load all tools
        },
    });

    // Load the structured chat prompt template
    const prompt = ChatPromptTemplate.fromMessages([
        ['system', 'You are a helpful assistant'],
        ['placeholder', '{chat_history}'],
        ['human', '{input}'],
        ['placeholder', '{agent_scratchpad}'],
    ]);

    // Fetch tools from toolkit
    const tools = hederaAgentToolkit.getTools();

    // Create the underlying agent
    const agent = createToolCallingAgent({
        llm,
        tools,
        prompt,
    });

    // Wrap everything in an executor that will maintain memory
    const agentExecutor = new AgentExecutor({
        agent,
        tools,
    });

    const response = await agentExecutor.invoke({ input: "what's my balance?" });
    console.log(response);
}

main().catch(console.error);