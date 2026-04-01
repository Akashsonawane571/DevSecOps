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
                git clone --depth=1 https://github.com/Akashsonawane571/DevSecOps.git temp_repo
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

        /*stage('SBOM Generation (Syft)') {
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
        } */

        stage('OSV Risk Enrichment') {
            steps {
                sh '''
                echo "Running OSV enrichment..."

                cat << 'EOF' > osv_scan.sh
#!/bin/bash
SBOM="sca/sbom/sbom.json"
OUTPUT="sca/reports/osv-report.json"

echo "[" > $OUTPUT

FIRST=1

jq -c '.artifacts[]? // empty' $SBOM | while read pkg; do
  NAME=$(echo $pkg | jq -r '.name')
  VERSION=$(echo $pkg | jq -r '.version')

  RESP=$(curl -s https://api.osv.dev/v1/query -d "{
    \\"package\\": {\\"name\\": \\"$NAME\\"},
    \\"version\\": \\"$VERSION\\"
  }")

  if [ $FIRST -eq 0 ]; then
    echo "," >> $OUTPUT
  fi

  echo $RESP >> $OUTPUT
  FIRST=0
done

echo "]" >> $OUTPUT
EOF

                chmod +x osv_scan.sh
                ./osv_scan.sh
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
