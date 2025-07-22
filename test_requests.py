import bentoml
import argparse

def test_query(prompt: str):
    print(f"\n=== Testing Prompt: {prompt} ===")
    with bentoml.SyncHTTPClient("http://localhost:3000") as client:
        try:
            # First analyze the prompt
            print("\nAnalyzing prompt for security...")
            analysis = client.analyze(prompt=prompt)
            print("Analysis Result:")
            print(analysis)
            
            # Then try to generate SQL
            print("\nGenerating SQL...")
            result = client.generate(prompt=prompt)
            print("Generation Result:")
            print(result)
            
        except Exception as e:
            print("Error:", str(e))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test SQLShield with a custom prompt')
    parser.add_argument('prompt', help='The prompt to test with SQLShield')
    
    args = parser.parse_args()
    test_query(args.prompt) 