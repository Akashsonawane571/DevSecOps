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
                git clone --depth=1 https://github.com/akshaynalkol/YummyRestaurant_Website temp_repo
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

        /*stage('SBOM Generation (Syft)') {
            steps {
                sh '''
                echo "Generating SBOM using Syft..."
        
                mkdir -p sca/sbom
        
                docker run --rm \
                  -v $(pwd):/workspace \
                  anchore/syft:latest dir:/workspace/temp_repo/node_modules \
                  --output json=/workspace/sca/sbom/sbom.json
        
                echo "Verify SBOM:"
                jq '.artifacts[].type' sca/sbom/sbom.json | sort | uniq
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
        }

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

        stage('Policy Enforcement (FOSSA)') {
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
        }*/
        stage('Build Docker Image') {
            steps {
                sh '''
                set -e
        
                echo "Building Docker image..."
        
                TECH=$(cat tech_stack.txt)
                IMAGE="akashsonawane571/devsecops:latest"
        
                cd temp_repo
        
                echo "Detected stack: $TECH"
        
                if [ "$TECH" = "dockerfile" ]; then
        
                    echo "Using existing repository Dockerfile"
        
                elif [ "$TECH" = "static" ]; then
        
                    printf '%s\n' \
        'FROM nginx:alpine' \
        'WORKDIR /usr/share/nginx/html' \
        'COPY . .' \
        'EXPOSE 80' \
        'CMD ["nginx","-g","daemon off;"]' > Dockerfile
        
                elif [ "$TECH" = "react" ] || [ "$TECH" = "vue" ] || [ "$TECH" = "angular" ]; then
        
                    printf '%s\n' \
        FROM node:18 AS build
        WORKDIR /app
        
        COPY package*.json ./
        
        RUN npm cache clean --force
        RUN npm install --legacy-peer-deps
        
        COPY . .
        
        RUN npm run build
        
        FROM nginx:alpine
        RUN rm -rf /usr/share/nginx/html/*
        COPY --from=build /app/build /usr/share/nginx/html
        COPY --from=build /app/dist /usr/share/nginx/html
        EXPOSE 80
        CMD ["nginx","-g","daemon off;"]
        
                elif [ "$TECH" = "nodejs" ]; then
        
                    printf '%s\n' \
        'FROM node:18' \
        'WORKDIR /app' \
        'COPY package*.json ./' \
        'RUN npm install' \
        'COPY . .' \
        'EXPOSE 3000' \
        'CMD ["npm","start"]' > Dockerfile
        
                elif [ "$TECH" = "python" ]; then
        
                    printf '%s\n' \
        'FROM python:3.11-slim' \
        'WORKDIR /app' \
        'COPY . .' \
        'RUN pip install --no-cache-dir -r requirements.txt || true' \
        'EXPOSE 5000' \
        'CMD ["python","app.py"]' > Dockerfile
        
                elif [ "$TECH" = "java" ]; then
        
                    printf '%s\n' \
        'FROM maven:3.9-eclipse-temurin-17 AS build' \
        'WORKDIR /app' \
        'COPY . .' \
        'RUN mvn clean package -DskipTests' \
        '' \
        'FROM eclipse-temurin:17-jre' \
        'WORKDIR /app' \
        'COPY --from=build /app/target/*.jar app.jar' \
        'EXPOSE 8080' \
        'CMD ["java","-jar","app.jar"]' > Dockerfile
        
                else
                    echo "Unsupported or unknown repository type: $TECH"
                    exit 1
                fi
        
                echo "Dockerfile preview:"
                head -20 Dockerfile || true
        
                docker build -t $IMAGE .
        
                echo "Image build completed: $IMAGE"
                '''
            }
        }
        stage('Run Application') {
            steps {
                sh '''
                echo "Stopping old container (if any)..."
                docker system prune -f
                docker rm -f universal-app || true
        
                TECH=$(cat tech_stack.txt)
                PORT=3000
        
                if [ "$TECH" = "static" ] || [ "$TECH" = "react" ] || [ "$TECH" = "vue" ] || [ "$TECH" = "angular" ]; then
                    PORT=80
        
                elif [ "$TECH" = "python" ]; then
                    PORT=5000
        
                elif [ "$TECH" = "java" ]; then
                    PORT=8080
        
                elif [ "$TECH" = "nodejs" ] || [ "$TECH" = "dockerfile" ]; then
                    PORT=3000
                fi
        
                echo "Detected stack: $TECH"
                echo "Using container port: $PORT"
        
                echo "Running container..."
                docker run -d -p 3000:$PORT --name universal-app akashsonawane571/devsecops:latest
        
                echo "Waiting for app to start..."
                sleep 120
        
                echo "Health check..."
                curl -I http://172.16.176.129:3000 || exit 1
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
        }
    } 
    post {
        always {
            echo "Archiving reports..."
    
            archiveArtifacts artifacts: 'sca/**/*.json, sast/**/*.json, image_reports/*.json, container_reports/*.json, dast_reports/*.json', fingerprint: true
        }
    }
}
