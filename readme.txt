1. Build & type-check
npm run build
npm run typecheck

2. run
npm run dev

3. Try it in another project
a. Option A – pack & install
npm pack          # creates yourorg-sdk-core-0.1.0.tgz
# in the consumer app:
npm i ../sdk-core/yourorg-sdk-core-0.1.0.tgz

b. Option B – link (during dev)
npm link
# in consumer app
npm link @yourorg/sdk-core