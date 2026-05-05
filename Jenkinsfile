pipeline {
    agent any

    environment {
        WORKSPACE_DIR = "${WORKSPACE}"
        SCA_DIR = "${WORKSPACE}/sca"
        FOSSA_API_KEY = credentials('fossa-api-key')  // store in Jenkins credentials
        OPENAI_API_KEY = credentials('openai-api-key')
        SONAR_SCANNER = tool name: 'sonar-scanner'
        SONAR_URL =  'http://16.170.213.108:9000'   //ip of sonarqube
    }

    stages {

        stage('Clean Workspace') {
            steps {
                echo "Cleaning workspace..."
                deleteDir()
            }
        }

        stage('Clone Repository') {
            steps {
                echo "Cloning repository..."
                sh '''
                git clone --depth=1 https://github.com/juice-shop/juice-shop.git temp_repo
                '''
            }
        }

        stage('Verify Repo Structure') {
            steps {
                sh '''
                echo "Repo structure:"
                ls -R temp_repo | head -n 50
                '''
            }
        }

        stage('Prepare SCA Directories') {
            steps {
                sh '''
                mkdir -p sca/sbom sca/reports sca/logs
                '''
            }
        }

        /*stage('Install Dependencies') {
            steps {
                sh '''
                echo "Installing dependencies with cache..."
        
                mkdir -p .npm-cache
        
                cd temp_repo
                npm install --ignore-scripts --cache ../.npm-cache --prefer-offline
                '''
            }
        }*/
        stage('Detect Tech Stack') {
            steps {
                sh '''
                echo "Detecting repository technology..."
        
                cd temp_repo
        
                TECH="unknown"
        
                if [ -f Dockerfile ]; then
                    TECH="dockerfile"
        
                elif [ -f package.json ]; then
                    if grep -qi "react" package.json; then
                        TECH="react"
                    elif grep -qi "vue" package.json; then
                        TECH="vue"
                    elif grep -qi "angular" package.json; then
                        TECH="angular"
                    else
                        TECH="nodejs"
                    fi
        
                elif [ -f requirements.txt ] || [ -f app.py ] || [ -f manage.py ]; then
                    TECH="python"
        
                elif [ -f pom.xml ] || [ -f build.gradle ]; then
                    TECH="java"
        
                elif [ -f index.html ]; then
                    TECH="static"
        
                fi
        
                echo "$TECH" > ../tech_stack.txt
        
                echo "Detected stack: $TECH"
                '''
            }
        }

        /*stage('SBOM Generation (Universal Syft)') {
            steps {
                sh '''
                set -e
        
                echo "Starting Universal SBOM generation..."
        
                mkdir -p sca/sbom
        
                cd temp_repo
        
                echo "Detecting best scan target..."
        
                TARGET="dir:/workspace/temp_repo"
        
                # Priority 1: node_modules (NodeJS)
                if [ -d node_modules ]; then
                    echo "Node.js project detected → scanning node_modules"
                    TARGET="dir:/workspace/temp_repo/node_modules"
        
                # Priority 2: Python virtual env
                elif [ -d venv ] || [ -f requirements.txt ]; then
                    echo "Python project detected → scanning full repo"
                    TARGET="dir:/workspace/temp_repo"
        
                # Priority 3: Java (jar/target)
                elif [ -d target ]; then
                    echo "Java project detected → scanning build artifacts"
                    TARGET="dir:/workspace/temp_repo/target"
        
                # Priority 4: Dockerfile present
                elif [ -f Dockerfile ]; then
                    echo "Docker project detected → scanning filesystem"
                    TARGET="dir:/workspace/temp_repo"
        
                # Fallback
                else
                    echo "Unknown project → fallback scan"
                    TARGET="dir:/workspace/temp_repo"
                fi
        
                echo "Using scan target: $TARGET"
        
                cd ..
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  anchore/syft:latest $TARGET \
                  --scope all-layers \
                  --output json=/workspace/sca/sbom/sbom.json
        
                echo "SBOM generated successfully"
        
                echo "Quick validation:"
                jq '.artifacts | length' sca/sbom/sbom.json
        
                echo "Top packages:"
                jq -r '.artifacts[].name' sca/sbom/sbom.json | head -n 20
                '''
            }
        }

        stage('Vulnerability Scan (Grype)') {
            steps {
                sh '''
                echo "Running Grype scan..."
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  anchore/grype:latest sbom:/workspace/sca/sbom/sbom.json \
                  -o json > sca/reports/grype-report.json
                '''
            }
        }

        stage('Vulnerability Scan (Trivy)') {
            steps {
                sh '''
                echo "Running Trivy scan..."
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  aquasec/trivy:0.49.1 fs /workspace/temp_repo \
                  --format json \
                  -o /workspace/sca/reports/trivy-report.json
        
                echo "Verifying Trivy report..."
                ls -l sca/reports/
                '''
            }
        }*/

        stage('OSV Risk Enrichment') {
            steps {
                sh '''
                echo "Running OSV enrichment..."
        
                SBOM="sca/sbom/sbom.json"
                OUTPUT="sca/reports/osv-report.json"
        
                mkdir -p sca/reports
        
                if [ ! -f "$SBOM" ]; then
                  echo "SBOM not found!"
                  exit 1
                fi
        
                echo "[" > $OUTPUT
                FIRST=1
        
                jq -r '.artifacts[] | select(.type=="npm") | "\\(.name) \\(.version)"' $SBOM | while read NAME VERSION; do
        
                  echo "Scanning $NAME@$VERSION"
        
                  RESP=$(curl -s --max-time 10 https://api.osv.dev/v1/query -d "{
                    \\"package\\": {
                      \\"name\\": \\"$NAME\\",
                      \\"ecosystem\\": \\"npm\\"
                    },
                    \\"version\\": \\"$VERSION\\"
                  }")
        
                  if [ "$RESP" != "{}" ]; then
                    if [ $FIRST -eq 0 ]; then
                      echo "," >> $OUTPUT
                    fi
        
                    echo "$RESP" >> $OUTPUT
                    FIRST=0
                  fi
        
                done
        
                echo "]" >> $OUTPUT
        
                echo "OSV scan completed"
                ls -l sca/reports/
                head -n 20 sca/reports/osv-report.json
                '''
            }
        }

        /*stage('Policy Enforcement (FOSSA)') {
            steps {
                sh '''
                echo "Running FOSSA analysis + policy check..."
        
                mkdir -p sca/reports
        
                docker run --rm \
                  -e FOSSA_API_KEY=$FOSSA_API_KEY \
                  -v $(pwd):/workspace \
                  alpine:latest sh -c "
                    apk add --no-cache curl bash git nodejs npm &&
                    curl -H 'Cache-Control: no-cache' https://raw.githubusercontent.com/fossas/fossa-cli/master/install-latest.sh | bash &&
        
                    cd /workspace/temp_repo &&
        
                    echo 'Running analyze...'
                    fossa analyze
        
                    echo 'Running policy test...'
                    fossa test
        
                    echo 'Saving local report...'
                    fossa analyze --output --json > /workspace/sca/reports/fossa-report.json
                  "
        
                echo "FOSSA report:"
                ls -l sca/reports/
                head -n 20 sca/reports/fossa-report.json
                '''
            }
        }

        stage('CI/CD Gate (Trivy + Report)') {
            steps {
                sh '''
                echo "Running Trivy scan and generating report..."
        
                mkdir -p sca/reports
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  aquasec/trivy:0.49.1 fs /workspace/temp_repo \
                  --severity HIGH,CRITICAL \
                  --format json \
                  -o /workspace/sca/reports/trivy-report.json
        
                echo "Trivy report generated:"
                ls -l sca/reports/
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  aquasec/trivy:0.49.1 fs /workspace/temp_repo \
                  --exit-code 1 \
                  --severity HIGH,CRITICAL
                '''
            }
        }

        stage('SAST Scan (Semgrep)') {
            steps {
                sh '''
                echo "Running Semgrep scan..."

                mkdir -p sast/reports

                docker run --rm \
                  -v $(pwd):/workspace \
                  returntocorp/semgrep \
                  semgrep scan /workspace/temp_repo \
                  --config=auto \
                  --json \
                  --output=/workspace/sast/reports/semgrep-report.json

                echo "Semgrep report:"
                ls -l sast/reports/
                '''
            }
        }

        stage('SonarQube Scan') {
            steps {
                echo 'Starting SonarQube SAST Scan...'
                withSonarQubeEnv('sonarqube') {
                    withCredentials([string(credentialsId: 'SONAR_TOKEN', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            cd temp_repo
                            $SONAR_SCANNER/bin/sonar-scanner \
                              -Dsonar.projectKey=devsecops-test \
                              -Dsonar.sources=. \
                              -Dsonar.host.url=$SONAR_URL \
                              -Dsonar.token=$SONAR_TOKEN
                        '''
                    }
                }
            }
        }
        stage('Build Docker Image') {
            steps {
                sh '''
                set -e
        
                echo "Building Docker image..."
        
                TECH=$(cat tech_stack.txt)
                IMAGE="akashsonawane571/devsecops:latest"
        
                cd temp_repo
        
                echo "Detected stack: $TECH"
        
                # Always start fresh
                if [ "$TECH" = "dockerfile" ]; then
        
                    echo "Using existing repository Dockerfile"
        
                else
                    rm -f Dockerfile
                fi
        
                if [ "$TECH" = "dockerfile" ]; then
        
                    echo "Using existing repository Dockerfile"
        
                elif [ "$TECH" = "static" ]; then
        
                    echo 'FROM nginx:alpine' > Dockerfile
                    echo 'WORKDIR /usr/share/nginx/html' >> Dockerfile
                    echo 'COPY . .' >> Dockerfile
                    echo 'EXPOSE 80' >> Dockerfile
                    echo 'CMD ["nginx","-g","daemon off;"]' >> Dockerfile
        
                elif [ "$TECH" = "react" ] || [ "$TECH" = "vue" ] || [ "$TECH" = "angular" ]; then
        
                    echo 'FROM node:18 AS build' > Dockerfile
                    echo 'WORKDIR /app' >> Dockerfile
                    echo 'COPY package*.json ./' >> Dockerfile
                    echo 'RUN npm cache clean --force' >> Dockerfile
                    echo 'RUN npm install --legacy-peer-deps --include=dev' >> Dockerfile
                    echo 'COPY . .' >> Dockerfile
                    echo 'RUN npm run build' >> Dockerfile
                    echo 'RUN if [ -d build ]; then cp -r build /output; elif [ -d dist ]; then cp -r dist /output; else mkdir /output; fi' >> Dockerfile
                    echo 'FROM nginx:alpine' >> Dockerfile
                    echo 'RUN rm -rf /usr/share/nginx/html/*' >> Dockerfile
                    echo 'COPY --from=build /output /usr/share/nginx/html' >> Dockerfile
                    echo 'EXPOSE 80' >> Dockerfile
                    echo 'CMD ["nginx","-g","daemon off;"]' >> Dockerfile
        
                elif [ "$TECH" = "nodejs" ]; then
        
                    echo 'FROM node:18' > Dockerfile
                    echo 'WORKDIR /app' >> Dockerfile
                    echo 'COPY package*.json ./' >> Dockerfile
                    echo 'RUN npm cache clean --force' >> Dockerfile
                    echo 'RUN npm install --legacy-peer-deps' >> Dockerfile
                    echo 'COPY . .' >> Dockerfile
                    echo 'EXPOSE 3000' >> Dockerfile
                    echo 'CMD ["npm","start"]' >> Dockerfile
        
                elif [ "$TECH" = "python" ]; then
        
                    echo 'FROM python:3.11-slim' > Dockerfile
                    echo 'WORKDIR /app' >> Dockerfile
                    echo 'COPY . .' >> Dockerfile
                    echo 'RUN pip install --no-cache-dir -r requirements.txt || true' >> Dockerfile
                    echo 'EXPOSE 5000' >> Dockerfile
                    echo 'CMD ["python","app.py"]' >> Dockerfile
        
                elif [ "$TECH" = "java" ]; then
        
                    echo 'FROM maven:3.9-eclipse-temurin-17 AS build' > Dockerfile
                    echo 'WORKDIR /app' >> Dockerfile
                    echo 'COPY . .' >> Dockerfile
                    echo 'RUN mvn clean package -DskipTests' >> Dockerfile
                    echo 'FROM eclipse-temurin:17-jre' >> Dockerfile
                    echo 'WORKDIR /app' >> Dockerfile
                    echo 'COPY --from=build /app/target/*.jar app.jar' >> Dockerfile
                    echo 'EXPOSE 8080' >> Dockerfile
                    echo 'CMD ["java","-jar","app.jar"]' >> Dockerfile
        
                else
                    echo "Unsupported or unknown repository type: $TECH"
                    exit 1
                fi
        
                echo "Dockerfile preview:"
                cat Dockerfile
        
                docker build --no-cache -t $IMAGE .
        
                echo "Image build completed: $IMAGE"
                '''
            }
        }
        stage('Run Application') {
            steps {
                sh '''
                set -e
        
                echo "Preparing to run application on port 3000..."
                docker system prune -f
                # Remove old known containers
                docker rm -f universal-app >/dev/null 2>&1 || true
                docker rm -f juice-app >/dev/null 2>&1 || true
        
                # Check if port 3000 is in use
                if ss -tulpn | grep -q ':3000 '; then
                    echo "Port 3000 is already in use."
        
                    # Find container using port 3000 and remove it
                    CONTAINER_ID=$(docker ps -q --filter publish=3000)
        
                    if [ -n "$CONTAINER_ID" ]; then
                        echo "Removing container using port 3000: $CONTAINER_ID"
                        docker rm -f $CONTAINER_ID
                    else
                        echo "Port 3000 used by non-docker process."
                        echo "Please free the port manually."
                        exit 1
                    fi
                fi
        
                TECH=$(cat tech_stack.txt)
                CONTAINER_PORT=3000
        
                if [ "$TECH" = "static" ] || [ "$TECH" = "react" ] || [ "$TECH" = "vue" ] || [ "$TECH" = "angular" ]; then
                    CONTAINER_PORT=80
                elif [ "$TECH" = "python" ]; then
                    CONTAINER_PORT=5000
                elif [ "$TECH" = "java" ]; then
                    CONTAINER_PORT=8080
                fi
        
                echo "Detected stack: $TECH"
                echo "Running container port: $CONTAINER_PORT"
                echo "Host port: 3000"
        
                docker run -d \
                  -p 3000:$CONTAINER_PORT \
                  --name universal-app \
                  akashsonawane571/devsecops:latest
        
                echo "Waiting for application startup..."
                sleep 60
        
                echo "Health check..."
                curl -I http://172.16.176.129:3000 || exit 1
        
                echo "Application started successfully."
                '''
            }
        }
        stage('Container Runtime Scan (Trivy Docker)') {
            steps {
                sh '''
                echo "Scanning running containers using Trivy container..."
        
                mkdir -p container_reports
        
                for container in $(docker ps -q); do
                  pid=$(docker inspect --format '{{.State.Pid}}' "$container")
                  name=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^\\/\\|\\/$//g')
        
                  echo "Scanning container $name (PID: $pid)..."
        
                  docker run --rm \
                    --pid=host \
                    -v /proc:/proc \
                    -v $(pwd):/workspace \
                    aquasec/trivy:0.49.1 fs \
                    --format json \
                    -o /workspace/container_reports/container_report_${name}.json \
                    /proc/$pid/root || echo "Failed to scan $name"
                done
        
                echo "Container scan complete"
                ls -l container_reports/
                '''
            }
        }
        stage('DAST Scan (OWASP ZAP)') {
            steps {
                sh '''
                echo "Running OWASP ZAP scan..."
        
                mkdir -p dast_reports
        
                docker run --rm \
                  --network host \
                  -v $(pwd)/dast_reports:/zap/wrk \
                  zaproxy/zap-stable \
                  zap-baseline.py \
                  -t http://172.16.176.129:3000 \
                  -J zap-report.json || true
        
                echo "ZAP scan completed"
                ls -l dast_reports/
                '''
            }
        }
        stage('DAST Scan (Nuclei)') {
            steps {
                sh '''
                echo "Running Nuclei scan..."
        
                mkdir -p dast_reports
        
                docker run --rm \
                  --network host \
                  -v $(pwd)/dast_reports:/workspace \
                  projectdiscovery/nuclei:latest \
                  -u http://172.16.176.129:3000 \
                  -jsonl \
                  -o /workspace/nuclei-report.json
        
                echo "Nuclei scan completed"
                ls -l dast_reports/
                '''
            }
        }
        stage('Upload Reports to DefectDojo') {
            steps {
                withCredentials([string(credentialsId: 'DEFECTDOJO_TOKEN', variable: 'DD_TOKEN')]) {
                    sh '''
                    echo "Uploading all reports to DefectDojo..."
        
                    DD_URL="http://172.16.176.129:8081/api/v2/import-scan/"
                    PRODUCT="DevSecOps Project"
                    ENGAGEMENT="Jenkins Pipeline Run"
        
                    upload_report() {
                      FILE=$1
                      TYPE=$2
        
                      if [ -f "$FILE" ]; then
                        echo "Uploading $FILE as $TYPE"
        
                        curl -s -X POST "$DD_URL" \
                          -H "Authorization: Token $DD_TOKEN" \
                          -F "file=@$FILE" \
                          -F "scan_type=$TYPE" \
                          -F "product_name=$PRODUCT" \
                          -F "engagement_name=$ENGAGEMENT" \
                          -F "active=true" \
                          -F "verified=true" \
                          || echo "Failed to upload $FILE"
                      else
                        echo "Skipping $FILE (not found)"
                      fi
                    }
        
                    echo "==== SAST ===="
                    upload_report "sast/reports/semgrep-report.json" "Semgrep JSON Report"
        
                    echo "==== SCA ===="
                    upload_report "sca/reports/trivy-report.json" "Trivy Scan"
                    upload_report "sca/reports/grype-report.json" "Grype Scan"
        
                    # Optional (future support / generic import)
                    upload_report "sca/sbom/sbom.json" "CycloneDX"
                    upload_report "sca/reports/osv-report.json" "Generic Findings Import"
                    upload_report "sca/reports/fossa-report.json" "Generic Findings Import"
        
                    echo "==== IMAGE SCAN ===="
                    upload_report "image_reports/final_image_scan.json" "Trivy Scan"
        
                    echo "==== CONTAINER SCAN ===="
                    upload_report "container_reports/container_report_juice-app.json" "Trivy Scan"
        
                    echo "==== DAST ===="
                    upload_report "dast_reports/zap-report.json" "ZAP Scan"
                    upload_report "dast_reports/nuclei-report.json" "Nuclei Scan"
        
                    echo "All uploads completed"
                    '''
                }
            }
        }*/
    } 
    post {
        always {
            echo "Archiving reports..."
    
            archiveArtifacts artifacts: 'sca/**/*.json, sast/**/*.json, image_reports/*.json, container_reports/*.json, dast_reports/*.json', fingerprint: true
        }
    }
}
