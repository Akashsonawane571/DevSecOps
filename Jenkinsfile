pipeline {
    agent any

    environment {
        WORKSPACE_DIR = "${WORKSPACE}"
        SCA_DIR = "${WORKSPACE}/sca"
        FOSSA_API_KEY = credentials('fossa-api-key')  // store in Jenkins credentials
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
        stage('Install Dependencies') {
            steps {
                sh '''
                echo "Installing dependencies (no build)..."
        
                cd temp_repo
                npm ci --ignore-scripts
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
                  anchore/syft:latest dir:/workspace/temp_repo \
                  -o json \
                  --file /workspace/sca/sbom/sbom.json
        
                echo "Verifying SBOM location..."
                pwd
                ls -l sca/sbom/
                '''
            }
        }
        /*stage('Vulnerability Scan (Grype)') {
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
        } */

        stage('OSV Risk Enrichment') {
            steps {
                sh '''
                echo "Running OSV enrichment..."
        
                SBOM="sca/sbom/sbom.json"
                OUTPUT="sca/reports/osv-report.json"
        
                mkdir -p sca/reports
        
                # Check SBOM exists
                if [ ! -f "$SBOM" ]; then
                  echo "❌ SBOM not found!"
                  exit 1
                fi
        
                echo "[" > $OUTPUT
                FIRST=1
        
                jq -c '.artifacts[]? // empty' $SBOM | while read pkg; do
        
                  NAME=$(echo $pkg | jq -r '.name')
                  VERSION=$(echo $pkg | jq -r '.version')
                  TYPE=$(echo $pkg | jq -r '.type')
        
                  # Ecosystem mapping
                  if [ "$TYPE" = "npm" ]; then
                    ECOSYSTEM="npm"
                  elif [ "$TYPE" = "python" ]; then
                    ECOSYSTEM="PyPI"
                  elif [ "$TYPE" = "java" ]; then
                    ECOSYSTEM="Maven"
                  else
                    continue
                  fi
        
                  echo "Scanning $NAME@$VERSION ($ECOSYSTEM)"
        
                  RESP=$(curl -s --max-time 10 https://api.osv.dev/v1/query -d "{
                    \\"package\\": {
                      \\"name\\": \\"$NAME\\",
                      \\"ecosystem\\": \\"$ECOSYSTEM\\"
                    },
                    \\"version\\": \\"$VERSION\\"
                  }")
        
                  if [ "$RESP" != "{}" ]; then
                    if [ $FIRST -eq 0 ]; then
                      echo "," >> $OUTPUT
                    fi
        
                    echo $RESP >> $OUTPUT
                    FIRST=0
                  fi
        
                done
        
                echo "]" >> $OUTPUT
        
                echo "✅ OSV scan completed"
        
                # Debug
                ls -l sca/reports/
                head -n 20 sca/reports/osv-report.json
                '''
            }
        }

        stage('Policy Enforcement (FOSSA)') {
            steps {
                sh '''
                echo "Running FOSSA analysis..."

                docker run --rm \
                  -u root \
                  -e FOSSA_API_KEY=$FOSSA_API_KEY \
                  -v $(pwd):/workspace \
                  alpine:latest sh -c "
                    apk add --no-cache curl bash git &&
                    curl -s https://raw.githubusercontent.com/fossas/fossa-cli/master/install.sh | bash &&
                    cd /workspace/temp_repo &&
                    fossa analyze
                  "
                '''
            }
        }

        stage('CI/CD Gate (Trivy Fail on High/Critical)') {
            steps {
                sh '''
                echo "Applying CI/CD security gate..."

                docker run --rm \
                  -u root \
                  -v $(pwd):/workspace \
                  aquasec/trivy:latest fs /workspace/temp_repo \
                  --exit-code 1 \
                  --severity HIGH,CRITICAL
                '''
            }
        }
    }

    post {
        always {
            echo "Archiving reports..."
    
            archiveArtifacts artifacts: 'sca/**/*.json', fingerprint: true
        }
    }
}
