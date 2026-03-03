import subprocess, sys

steps = [
    "models/isolation_forest.py",
    "models/lof_model.py",
    "models/autoencoder.py",
    "models/ensemble.py",
]

failed_steps = []

for step in steps:
    print(f"\n{'='*50}\nRunning {step}\n{'='*50}")
    result = subprocess.run([sys.executable, step])
    if result.returncode != 0:
        print(f"\n⚠️  {step} failed with exit code {result.returncode}")
        failed_steps.append(step)
    else:
        print(f"✓ {step} completed successfully")

if failed_steps:
    print(f"\n{'='*50}")
    print(f"⚠️  {len(failed_steps)} step(s) failed:")
    for step in failed_steps:
        print(f"  - {step}")
    print(f"{'='*50}")
    sys.exit(1)
else:
    print(f"\n{'='*50}")
    print("✓ All models completed successfully!")
    print(f"{'='*50}")