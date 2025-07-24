# CI/CD Pipeline for SimpleTodoApp

Bu README dosyası, `SimpleTodoApp` projesi için tasarlanmış Sürekli Entegrasyon/Sürekli Dağıtım (CI/CD) pipeline'ını detaylandırmaktadır. Pipeline, kod değişikliklerinin otomatik olarak test edilmesini, derlenmesini, konteyner imajlarının oluşturulmasını, güvenlik analizlerinin yapılmasını ve uygulamaların Kubernetes ortamına dağıtılmasını sağlar. Bu süreç, projenin hızlı, güvenilir ve güvenli bir şekilde geliştirilmesini ve dağıtılmasını hedefler.

## İçindekiler

1.  Genel Bakış
2.  Pipeline Tetikleyicileri
3.  Ortam Değişkenleri
4.  CI/CD Adımları (Jobs)
    *   Build ve Test (build-and-test)
    *   Dev Ortamına Dağıtım (deploy-to-dev)
    *   Dinamik Güvenlik Analizi (dynamic-analysis-DAST)
    *   Manuel Onay (manual-approval-for-prod)
    *   Prod Ortamına Dağıtım (deploy-to-prod)
5.  Kullanılan Araçlar ve Teknolojiler
6.  CICD Felsefesi




## 1. Genel Bakış

Bu CI/CD pipeline, `SimpleTodoApp` projesinin geliştirme ve dağıtım süreçlerini otomatikleştirmek için GitHub Actions üzerinde yapılandırılmıştır. Pipeline, kod kalitesini ve güvenliğini sağlamak amacıyla çeşitli statik ve dinamik analiz araçlarını entegre ederken, uygulamaların `dev` ve `prod` ortamlarına güvenli ve kontrollü bir şekilde dağıtımını yönetir. GitOps prensipleri ArgoCD aracı kullanılarak Kubernetes manifestleri üzerinden dağıtım tetiklenir.

Pipeline, aşağıdaki temel aşamalardan oluşur:

*   **Kod Değişikliklerinin Tetiklenmesi**: `main` veya `feature` dallarına yapılan `push` veya `pull_request` işlemleriyle ya da manuel olarak `workflow_dispatch` ile tetiklenir.
*   **Derleme ve Test**: Uygulama kodunun derlenmesi, bağımlılıkların yönetilmesi ve birim/entegrasyon testlerinin çalıştırılması.
*   **Güvenlik Analizleri**: Statik Uygulama Güvenlik Testi (SAST) ve Dinamik Uygulama Güvenlik Testi (DAST) araçları kullanılarak kod ve dağıtılan uygulamanın güvenlik açıklarının taranması.
*   **Konteyner İmajı Oluşturma ve Yönetimi**: Uygulamanın Docker imajının oluşturulması, etiketlenmesi ve container registry olan Harbor'a gönderilmesi.
*   **Kubernetes Dağıtımı**: Uygulamanın `dev` ve `prod` Kubernetes ortamlarına Kustomize ve GitOps (ArgoCD) aracılığıyla dağıtılması.
*   **Manuel Onay**: Üretim ortamına dağıtımdan önce manuel onay adımı ile kontrol ve güvenlik sağlanması.

Bu yapı, geliştiricilerin daha hızlı iterasyon yapmasına, hataları erken aşamada tespit etmesine ve üretim ortamına güvenli bir şekilde dağıtım yapmasına olanak tanır.




## 2. Pipeline Tetikleyicileri

CI/CD pipeline, çeşitli olaylar tarafından otomatik olarak tetiklenebilir veya manuel olarak başlatılabilir. Bu esneklik, geliştirme sürecinin farklı aşamalarına uyum sağlar.

*   **`push` olayları**: `main` veya `feature` dallarına yapılan her kod `push` işlemi pipeline'ı tetikler. Bu, yeni kod değişikliklerinin sürekli olarak entegre edilmesini ve test edilmesini sağlar.

*   **`pull_request` olayları**: `main` veya `feature` dallarına açılan `pull_request`'ler pipeline'ı tetikler. Bu, kod birleştirilmeden önce değişikliklerin doğrulanmasını ve potansiyel sorunların erken tespit edilmesini sağlar.

*   **`workflow_dispatch`**: Bu tetikleyici, pipeline'ın GitHub Actions arayüzünden manuel olarak başlatılmasına olanak tanır. Manuel çalıştırmalar sırasında, kullanıcının `run-options` girdisi aracılığıyla belirli işleri (örneğin, sadece derleme işi veya tüm pipeline) çalıştırma seçeneği bulunur. Bu, özellikle hata ayıklama veya belirli bir iş akışını yeniden çalıştırma durumlarında faydalıdır.

```yaml
on:
  push:
    branches:
      - main
      - feature
  pull_request:
    branches:
      - main
      - feature
  workflow_dispatch:
    inputs:
      run-options:
        description: 'Select run-options. (mandatory)'
        required: true
        default: 'only-build-job'
        type: choice
        options:
        - only-build-job
        - run-all
```

Bu tetikleyiciler, geliştirme ekibine kod değişikliklerini hızlı bir şekilde doğrulamak ve dağıtım sürecini kontrol altında tutmak için gerekli otomasyonu ve esnekliği sağlar.

## 3. Ortam Değişkenleri

Pipeline genelinde kullanılan önemli ortam değişkenleri, yapılandırmanın merkezi ve kolay yönetilebilir olmasını sağlar. Bu değişkenler, uygulama adı, container registry bilgileri, GitOps deposu (manifest-mehmetkanus) ve uygulama kaynak dizinleri gibi kritik bilgileri içerir.

```yaml
env:
  APP_NAME: simple-todo-app
  HARBOR_URL: harbor.prod.goxdev.lol
  APP_IMAGE: harbor.prod.goxdev.lol/app-mehmetkanus/todoapp
  GITOPS_REPO: ${{ github.repository_owner }}/manifest-mehmetkanus
  DOCKERFILE_PATH: ./SimpleTodoApp/Dockerfile
  APP_SOURCE_DIR: ./SimpleTodoApp
  DEV_APP_URL: app.dev.goxdev.lol
  PROD_APP_URL: app.prod.goxdev.lol
```

*   **`APP_NAME`**: Uygulamanın adı (`simple-todo-app`).
*   **`HARBOR_URL`**: Konteyner imajlarının depolandığı Harbor registry URL adresi.
*   **`APP_IMAGE`**: Uygulamanın tam imaj yolu ve adı.
*   **`GITOPS_REPO`**: Kubernetes manifestlerinin bulunduğu GitOps deposunun adı. Bu depo, ArgoCD CD aracı tarafından izlenir.
*   **`DOCKERFILE_PATH`**: Uygulamanın Dockerfile dosyasının yolu.
*   **`APP_SOURCE_DIR`**: Uygulama kaynak kodunun bulunduğu dizin.
*   **`DEV_APP_URL`**: Geliştirme ortamında dağıtılan uygulamanın URL adresi.
*   **`PROD_APP_URL`**: Üretim ortamında dağıtılan uygulamanın URL adresi.

Bu ortam değişkenleri, pipeline adımlarının dinamik olarak yapılandırılmasını ve farklı ortamlar veya uygulamalar için kolayca yeniden kullanılabilmesini sağlar.

## 4. CI/CD Adımları (Jobs)

Pipeline, uygulamanın yaşam döngüsünün farklı aşamalarını temsil eden bir dizi işten (jobs) oluşur. Her iş, belirli bir görevi yerine getirir ve bir sonraki işin başlaması için ön koşul olabilir.

### Build ve Test (`build-and-test`)

Bu iş, uygulamanın kaynak kodunu derlemek, test etmek ve Docker imajını oluşturup Harbor registry'ye göndermekten sorumludur. Ayrıca, kod ve imaj üzerinde statik güvenlik analizleri (SAST) yapar.

*   **`runs-on: ubuntu-latest`**: İşin Ubuntu işletim sistemine sahip bir GitHub Actions runner üzerinde çalışacağını belirtir.
*   **`permissions`**: İşin ihtiyaç duyduğu izinleri tanımlar: `contents: read` (depo içeriğini okuma), `packages: write` (paket yazma) ve `pull-requests: write` (DAST yorumları için gerekli olabilir).

#### Adımlar:

1.  **Checkout Source Code**: Uygulamanın kaynak kodunu runner ortamına çeker.
    ```yaml
    - name: Checkout Source Code
      uses: actions/checkout@v4
    ```

2.  **Trivy Filesystem Scan (SAST)**: Kaynak kod üzerinde dosya sistemi tabanlı statik güvenlik analizi yapar. `CRITICAL` ve `HIGH` önem derecesindeki güvenlik açıklarını tarar ve düzeltilmemiş olanları göz ardı eder. Herhangi bir kritik veya yüksek güvenlik açığı bulunursa pipeline başarısız olur (`exit-code: '1'`).
    ```yaml
    - name: Trivy Filesystem Scan (SAST)
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        exit-code: '1'
        severity: 'CRITICAL,HIGH'
        ignore-unfixed: true
        format: table
    ```

3.  **Login to Harbor**: Docker imajını Harbor registry'ye göndermek için kimlik doğrulaması yapar. Harbor kullanıcı adı ve parolası GitHub Secrets olarak saklanır.
    ```yaml
    - name: Login to Harbor
      uses: docker/login-action@v3
      with:
        registry: ${{ env.HARBOR_URL }}
        username: ${{ secrets.HARBOR_USERNAME }}
        password: ${{ secrets.HARBOR_PASSWORD }}
    ```

4.  **Extract metadata (tags, labels) for Docker**: Docker imajı için etiketler (tag) ve meta veriler oluşturur. `github.sha` (commit hash) ve `latest` etiketleri kullanılır.
    ```yaml
    - name: Extract metadata (tags, labels) for Docker
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.APP_IMAGE }}
        tags: |
          ${{ github.sha }}
          latest
    ```

5.  **Build and Push Docker Image to Harbor**: Uygulamanın Dockerfile dosyasını kullanarak Docker imajını oluşturur ve etiketlenmiş imajı Harbor registry'ye gönderir.
    ```yaml
    - name: Build and Push Docker Image to Harbor
      id: push
      uses: docker/build-push-action@v6
      with:
        context: ${{ env.APP_SOURCE_DIR }}
        file: ${{ env.DOCKERFILE_PATH }}
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
    ```

6.  **Trivy Image Scan (SAST - Image)**: Oluşturulan Docker imajı üzerinde statik güvenlik analizi yapar. `CRITICAL` ve `HIGH` önem derecesindeki güvenlik açıklarını tarar ve düzeltilmemiş olanları göz ardı eder. Bu tarama, imajın içeriğindeki bilinen güvenlik açıklarını tespit etmeyi amaçlar.
    ```yaml
    - name: Trivy Image Scan (SAST - Image)
      uses: aquasecurity/trivy-action@0.28.0
      with:
        image-ref: '${{ env.APP_IMAGE }}:${{ github.sha }}'
        exit-code: '0'
        severity: 'CRITICAL,HIGH'
        ignore-unfixed: true
        format: 'table'
    ```

Bu iş, uygulamanın dağıtıma hazır bir Docker imajına dönüştürülmesini ve temel güvenlik kontrollerinden geçmesini sağlar.

### Dev Ortamına Dağıtım (`deploy-to-dev`)

Bu iş, uygulamanın geliştirme (dev) ortamına dağıtımını yönetir. GitOps prensiplerine uygun olarak, Kubernetes manifestlerinin bulunduğu GitOps deposunu güncelleyerek dağıtımı tetikler.

*   **`needs: build-and-test`**: Bu işin `build-and-test` işi başarıyla tamamlandıktan sonra çalışacağını belirtir.
*   **`if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'`**: Bu koşul, işin yalnızca `workflow_dispatch` olayı tarafından tetiklenmediğinde veya `workflow_dispatch` ile tetiklendiğinde `run-all` seçeneği belirlendiğinde çalışmasını sağlar.

#### Adımlar:

1.  **Update GitOps deployment repo**: Bu adım, uygulamanın yeni imaj etiketini (tag) GitOps deposundaki `dev` ortamına ait `kustomization.yaml` dosyasına yazar. Bu değişiklik, ArgoCD aracı tarafından algılanacak ve uygulamanın `dev` ortamında güncellenmiş imaj ile dağıtılmasını tetikleyecektir.

    ```bash
    - name: Update GitOps deployment repo
      run: |
        git clone https://${{ secrets.GITOPS_PAT }}@github.com/${{ env.GITOPS_REPO }} gitops
        cd gitops

        # Güncel image tag\`i
        export APP_IMAGE="${{ env.APP_IMAGE }}"
        export TAG="${{ github.sha }}"

        sed -i "s|newTag: .*|newTag: ${TAG}|g" ./overlays/dev/kustomization.yaml

        git config user.name "GitHub Actions"
        git config user.email "actions@github.com"
        git add ./overlays/dev/kustomization.yaml
        git commit -m "Update image:${{ env.APP_IMAGE }} tag to ${TAG}"
        git push origin main
    ```

Bu iş, uygulamanın `dev` ortamında sürekli olarak güncel kalmasını ve geliştiricilerin en son değişiklikleri hızlı bir şekilde test etmesini sağlar.

### Dinamik Güvenlik Analizi (`dynamic-analysis-DAST`)

Bu iş, uygulama `dev` ortamına dağıtıldıktan sonra dinamik güvenlik analizi (DAST) yapar. Bu analiz, çalışan uygulamanın güvenlik açıklarını tespit etmeyi amaçlar.

*   **`needs: deploy-to-dev`**: Bu işin `deploy-to-dev` işi başarıyla tamamlandıktan sonra çalışacağını belirtir.
*   **`if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'`**: Bu koşul, işin yalnızca `workflow_dispatch` olayı tarafından tetiklenmediğinde veya `workflow_dispatch` ile tetiklendiğinde `run-all` seçeneği belirlendiğinde çalışmasını sağlar.

#### Adımlar:

1.  **Uygulamanın hazır olmasını bekle**: DAST taramasına başlamadan önce uygulamanın `dev` ortamında tamamen ayağa kalktığından emin olmak için kısa bir bekleme süresi ekler.
    ```yaml
    - name: Uygulamanın hazır olmasını bekle.
      run: |
        echo "app.dev.mehmetkanus.com sitesinin hazır olmasını bekleyin."
        sleep 30
    ```

2.  **ZAP Baseline Scan (DAST)**: OWASP ZAP (Zed Attack Proxy) kullanarak uygulamanın temel güvenlik taramasını yapar. Bu tarama, dağıtılan uygulamanın bilinen güvenlik açıklarına karşı kontrol edilmesini sağlar. Tarama sonuçları GitHub Actions iş akışı çıktısında görüntülenebilir ve daha sonra manuel onay adımında referans olarak kullanılabilir.
    ```yaml
    - name: ZAP Baseline Scan (DAST)
      uses: zaproxy/action-baseline@v0.14.0
      with:
        token: ${{ secrets.GITOPS_PAT }}
        docker_name: 'ghcr.io/zaproxy/zaproxy:stable'
        target: 'https://${{ env.DEV_APP_URL }}'
        cmd_options: '-a'
    ```

Bu iş, uygulamanın çalışma zamanı güvenliğini doğrulamak için kritik bir adımdır ve potansiyel zafiyetlerin üretim ortamına ulaşmadan önce tespit edilmesine yardımcı olur.

### Manuel Onay Adımı (`manual-approval-for-prod`)

Bu iş, uygulamanın üretim ortamına dağıtılmasından önce manuel bir onay süreci sağlar. Bu, kritik dağıtımlar için ek bir güvenlik katmanı ve kontrol noktası sunar.

*   **`needs: dynamic-analysis-DAST`**: Bu işin `dynamic-analysis-DAST` işi başarıyla tamamlandıktan sonra çalışacağını belirtir.
*   **`if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'`**: Bu koşul, işin yalnızca `workflow_dispatch` olayı tarafından tetiklenmediğinde veya `workflow_dispatch` ile tetiklendiğinde `run-all` seçeneği belirlendiğinde çalışmasını sağlar.

#### Adımlar:

1.  **Manual approval to deploy to production**: `trstringer/manual-approval@v1` GitHub Action kullanılarak bir manuel onay adımı oluşturulur. Bu adım, belirtilen onaylayıcılardan (`mehmetkanus17`) en az birinin onayı olmadan pipeline'ın ilerlemesini engeller. Onay süreci, bir GitHub Issue oluşturularak yönetilir ve DAST raporlarına bir bağlantı içerir.
    ```yaml
    - name: Manual approval to deploy to production
      uses: trstringer/manual-approval@v1
      with:
        secret: ${{ secrets.GITOPS_PAT }}
        approvers: mehmetkanus17
        minimum-approvals: 1
        issue-title: "Deployment Approval for Production - ${{ github.sha }}"
        issue-body: |
          Uygulama ${{ github.sha }} versiyonu üretim ortamına dağıtılmak üzere hazır.
          Lütfen inceleyin ve onaylamak için \'approve\' veya reddetmek için \'deny\' yazın.
          DAST Raporları: [ZAP Raporları](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})
    ```

Bu manuel onay adımı, üretim ortamına yapılan dağıtımların insan müdahalesi ve onayı ile gerçekleşmesini sağlayarak olası hataları veya güvenlik açıklarını önlemeye yardımcı olur.

### Prod Ortamına Dağıtım (`deploy-to-prod`)

Bu iş, uygulamanın üretim (prod) ortamına dağıtımını yönetir. `deploy-to-dev` işine benzer şekilde, GitOps prensiplerine uygun olarak Kubernetes manifestlerinin bulunduğu GitOps deposunu güncelleyerek dağıtımı tetikler.

*   **`needs: manual-approval-for-prod`**: Bu işin `manual-approval-for-prod` işi başarıyla tamamlandıktan ve onaylandıktan sonra çalışacağını belirtir.
*   **`if: github.event_name != 'workflow_dispatch' || inputs.run-options == 'run-all'`**: Bu koşul, işin yalnızca `workflow_dispatch` olayı tarafından tetiklenmediğinde veya `workflow_dispatch` ile tetiklendiğinde `run-all` seçeneği belirlendiğinde çalışmasını sağlar.

#### Adımlar:

1.  **Update GitOps deployment repo**: Bu adım, uygulamanın yeni imaj etiketini (tag) GitOps deposundaki `prod` ortamına ait `kustomization.yaml` dosyasına yazar. Bu değişiklik, ArgoCD tarafından algılanacak ve uygulamanın `prod` ortamında güncellenmiş imaj ile dağıtılmasını tetikleyecektir.

    ```bash
    - name: Update GitOps deployment repo
      run: |
        git clone https://${{ secrets.GITOPS_PAT }}@github.com/${{ env.GITOPS_REPO }} gitops
        cd gitops

        # Güncel image tag\`i
        export APP_IMAGE="${{ env.APP_IMAGE }}"
        export TAG="${{ github.sha }}"

        sed -i "s|newTag: .*|newTag: ${TAG}|g" ./overlays/prod/kustomization.yaml

        git config user.name "GitHub Actions"
        git config user.email "actions@github.com"
        git add ./overlays/prod/kustomization.yaml
        git commit -m "Update image:${{ env.APP_IMAGE }} tag to ${TAG}"
        git push origin main
    ```

Bu iş, uygulamanın üretim ortamına güvenli ve otomatik bir şekilde dağıtılmasını sağlar, böylece en son kararlı sürüm kullanıcılar için erişilebilir hale gelir.

## 5. Kullanılan Araçlar ve Teknolojiler

Bu CI/CD pipeline, modern DevOps uygulamalarını desteklemek için çeşitli araç ve teknolojilerden faydalanmaktadır:

*   **GitHub Actions**: CI/CD iş akışlarını otomatikleştirmek için kullanılan ana platform.
*   **Docker**: Uygulama konteynerlerini oluşturmak ve yönetmek için kullanılır.
*   **Harbor**: Özel Docker imajlarının depolanması ve yönetilmesi için kullanılan container registry.
*   **Trivy**: Statik Uygulama Güvenlik Testi (SAST) için kullanılan açık kaynaklı bir güvenlik tarayıcısı. Hem dosya sistemi hem de Docker imajları üzerinde güvenlik açığı taraması yapar.
*   **OWASP ZAP (Zed Attack Proxy)**: Dinamik Uygulama Güvenlik Testi (DAST) için kullanılan açık kaynaklı bir web uygulaması güvenlik tarayıcısı.
*   **GitOps (Kustomize, ArgoCD)**: Kubernetes manifestlerini yönetmek ve uygulamaları Git deposundaki değişikliklere göre otomatik olarak dağıtmak için kullanılan prensip ve araçlar. Bu pipeline özelinde Kustomize ile manifestler özelleştirilir ve GitOps deposuna commit edilerek CD aracı tarafından dağıtım tetiklenir.
*   **Kubernetes**: Uygulamaların dağıtıldığı ve yönetildiği konteyner orkestrasyon platformu.
*   **`trstringer/manual-approval@v1`**: Üretim dağıtımlarından önce manuel onay adımı sağlamak için kullanılan GitHub Action.

Bu araçların birleşimi, `SimpleTodoApp` için sağlam, güvenli ve otomatik bir CI/CD süreci oluşturur.

## 6. CI/CD Felsefesi ile Uyum

Bu CI/CD pipeline, DevOps Uygulama Görevi proje tarafından belirlenen temel felsefeler ve gereksinimlerle tam uyum içindedir:

*   **Her şeyi "as code" olarak yapmak**: Tüm pipeline adımları, uygulama ve Kubernetes manifestleri (Kustomize ile) kod olarak tanımlanmıştır. Bu, versiyon kontrolü, tekrarlanabilirlik ve otomasyon sağlar.

*   **Doğru iş için doğru aracı kullanmak**: GitHub Actions CI için, Harbor imaj depolama için, Trivy ve ZAP güvenlik analizleri için, Kustomize ve GitOps (ArgoCD ile) dağıtım için kullanılmıştır. Her araç, belirli bir ihtiyacı karşılamak üzere seçilmiştir.

*   **Ortaya çıkacak yapının modüler ve genişleyebilir olması**: Pipeline, farklı ortamlar (`dev`, `prod`) için ayrı dağıtım adımları ve Kustomize overlayleri ile modüler bir yapıya sahiptir. Bu, gelecekteki genişlemelere ve yeni ortamların eklenmesine olanak tanır.

### CICD Felsefesi

CI/CD gereksinimleri, bu pipeline içinde aşağıdaki gibi karşılanmıştır:

*   **Kod Değişikliklerinin Tetiklenmesi**: `push` ve `pull_request` olayları ile pipeline tetiklenir. Ayrıca `workflow_dispatch` ile manuel tetikleme seçeneği sunulur.
*   **Statik Kod Analizi (SAST)**: Trivy kullanılarak dosya sistemi ve Docker imajı üzerinde SAST taramaları yapılır.
*   **Kod Derleme ve İmaj Oluşturma**: Uygulama kodu derlenir ve yeni bir konteyner imajı oluşturularak Harbor container registry'yene gönderilir.
*   **CD Aracının Tetiklenmesi**: CI aracı (GitHub Actions), Kubernetes manifestlerinin bulunduğu GitOps deposuna (örneğin `manifest-mehmetkanus`) gerekli değişiklikleri (`newTag` güncellemesi) push ederek CD aracını (ArgoCD) tetikler. Bu, CI aracının doğrudan dağıtım yapmaması, bunun yerine CD aracını tetiklemesi prensibine uyar.
*   **Dev ve Prod Ortamları**: Tek Kubernetes kümesi içinde `dev` ve `prod` namespace seviyesinde ayrılmış ortamlar bulunur. Ortama özel konfigürasyonlar Kustomize ile yönetilir.
*   **Dinamik Güvenlik Analizi (DAST)**: `dev` ortamına dağıtımdan sonra OWASP ZAP kullanılarak DAST taraması yapılır.
*   **Manuel Onay Adımı**: Üretim ortamına dağıtımdan önce manuel onay adımı (`trstringer/manual-approval`) eklenmiştir.

Bu README, `SimpleTodoApp` projesinin CI/CD süreçlerini anlamak ve yönetmek için kapsamlı bir rehber sunmaktadır.
