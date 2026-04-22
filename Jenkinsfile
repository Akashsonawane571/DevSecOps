pipeline {
    agent any

    environment {
        WORKSPACE_DIR = "${WORKSPACE}"
        SCA_DIR = "${WORKSPACE}/sca"
        FOSSA_API_KEY = credentials('fossa-api-key')  // store in Jenkins credentials
        OPENAI_API_KEY = credentials('openai-api-key')
        SONAR_SCANNER = tool name: 'sonar-scanner'
        SONAR_URL =  'http://13.62.100.36:9000'   //ip of sonarqube
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
        }

        stage('SBOM Generation (Syft)') {
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

        stage('AI Security Analysis') {
            steps {
                sh '''
                echo "Running AI analysis..."
        
                docker run --rm \
                  -e OPENAI_API_KEY=$OPENAI_API_KEY \
                  -v $(pwd):/workspace \
                  python:3.11-slim \
                  sh -c "
                    apt-get update && apt-get install -y wget &&
                    pip install requests &&
                    wget -O /workspace/ai_analysis.py https://raw.githubusercontent.com/Akashsonawane571/DevSecOps/main/ai/ai_analysis.py &&
                    python /workspace/ai_analysis.py
                  "
                '''
            }
        }

        stage('Generate PDF Report') {
            steps {
                sh '''
                echo "Generating PDF..."
    
                docker run --rm \
                  -v $(pwd):/workspace \
                  pandoc/core \
                  /workspace/sca/reports/ai-report.txt \
                  -o /workspace/sca/reports/ai-report.pdf
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

        /*stage('SonarQube Scan') {
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
                echo "Building Docker image..."
        
                cd temp_repo
        
                docker build -t akashsonawane571/devsecops:latest .
                '''
            }
        }
        /*stage('Image Scanning (Trivy Docker)') {
            environment {
                TRIVY_SEVERITY = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
            }
            steps {
                sh '''
                echo "Scanning Docker images using Trivy container..."
        
                mkdir -p image_reports
        
                IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
        
                if [ -z "$IMAGES" ]; then
                  echo "No images found"
                  exit 1
                fi
        
                for image in $IMAGES; do
                  name=$(echo "$image" | tr '/:' '_')
                  echo "Scanning image: $image"
        
                  docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v $(pwd):/workspace \
                    aquasec/trivy:0.49.1 image \
                    --format json \
                    --severity "$TRIVY_SEVERITY" \
                    -o /workspace/image_reports/image_report_${name}.json \
                    "$image"
                done
        
                echo "Image scan complete"
                ls -l image_reports/
                '''
            }
        }*/
        stage('Run Application') {
            steps {
                sh '''
                echo "Stopping old container (if any)..."
                docker rm -f juice-app || true
        
                echo "Running container..."
                docker run -d -p 3000:3000 --name juice-app akashsonawane571/devsecops:latest
        
                echo "Waiting for app to start..."
                sleep 20
        
                echo "Health check..."
                curl -I http://localhost:3000 || exit 1
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
                  owasp/zap2docker-stable \
                  zap-baseline.py \
                  -t http://localhost:3000 \
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
                  -u http://localhost:3000 \
                  -json \
                  -o /workspace/nuclei-report.json
        
                echo "Nuclei scan completed"
                ls -l dast_reports/
                '''
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
